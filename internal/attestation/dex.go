package attestation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type DexClient struct {
	baseURL      *url.URL
	redirectURL  string
	httpClient   *http.Client
	privateKey   *ecdsa.PrivateKey
	devLicenseID string
}

func NewDexClient(httpClient *http.Client, baseURL *url.URL, redirectURL string, privateKey *ecdsa.PrivateKey, devLicenseID string) *DexClient {
	return &DexClient{
		baseURL:      baseURL,
		redirectURL:  redirectURL,
		httpClient:   httpClient,
		privateKey:   privateKey,
		devLicenseID: devLicenseID,
	}
}

type TokenCache struct {
	mu       sync.Mutex
	token    string
	deadline time.Time
}

func (c *TokenCache) GetToken(ctx context.Context, dex *DexClient) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.deadline) {
		return c.token, nil
	}

	token, err := dex.getToken(ctx)
	if err != nil {
		return "", err
	}

	expiry, err := tokenExpiry(token)
	if err != nil {
		return "", err
	}

	deadline := expiry.Add(-30 * time.Second)
	if deadline.Before(time.Now()) {
		deadline = time.Now()
	}

	c.token = token
	c.deadline = deadline
	return token, nil
}

type challengeResponse struct {
	Challenge string `json:"challenge"`
	State     string `json:"state"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

func (c *DexClient) getToken(ctx context.Context) (string, error) {
	initParams := url.Values{}
	initParams.Set("domain", c.redirectURL)
	initParams.Set("client_id", c.devLicenseID)
	initParams.Set("response_type", "code")
	initParams.Set("scope", "openid email")
	initParams.Set("address", c.devLicenseID)

	challengeURL := c.baseURL.JoinPath("auth/web3/generate_challenge")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, challengeURL.String(), strings.NewReader(initParams.Encode()))
	if err != nil {
		return "", fmt.Errorf("build challenge request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("generate challenge: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("generate challenge status %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}

	var challengeResp challengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&challengeResp); err != nil {
		return "", fmt.Errorf("decode challenge response: %w", err)
	}

	signature, err := SignERC191(challengeResp.Challenge, c.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign challenge: %w", err)
	}

	submitParams := url.Values{}
	submitParams.Set("client_id", c.devLicenseID)
	submitParams.Set("domain", c.redirectURL)
	submitParams.Set("grant_type", "authorization_code")
	submitParams.Set("state", challengeResp.State)
	submitParams.Set("signature", signature)

	submitURL := c.baseURL.JoinPath("auth/web3/submit_challenge")
	submitReq, err := http.NewRequestWithContext(ctx, http.MethodPost, submitURL.String(), strings.NewReader(submitParams.Encode()))
	if err != nil {
		return "", fmt.Errorf("build submit challenge request: %w", err)
	}
	submitReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	submitResp, err := c.httpClient.Do(submitReq)
	if err != nil {
		return "", fmt.Errorf("submit challenge: %w", err)
	}
	defer submitResp.Body.Close()

	if submitResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(submitResp.Body, 4096))
		return "", fmt.Errorf("submit challenge status %d: %s", submitResp.StatusCode, bytes.TrimSpace(body))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(submitResp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", errors.New("token response did not include access_token")
	}

	return tokenResp.AccessToken, nil
}

func tokenExpiry(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, errors.New("token was not a JWT")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("decode token payload: %w", err)
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, fmt.Errorf("decode token claims: %w", err)
	}
	if claims.Exp == 0 {
		return time.Time{}, errors.New("token did not include exp")
	}

	return time.Unix(claims.Exp, 0), nil
}
