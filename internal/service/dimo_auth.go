package service

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sync"
	"time"

	shttp "github.com/DIMO-Network/shared/pkg/http"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
)

type DimoAuthService struct {
	authURL    url.URL
	clientID   common.Address
	domain     string
	privateKey *ecdsa.PrivateKey
	token      *jwt.Token
	logger     *zerolog.Logger
	m          sync.RWMutex
}

func NewDimoAuthService(logger *zerolog.Logger, settings *config.Settings) (*DimoAuthService, error) {
	ecdsaPrivateKey, err := crypto.HexToECDSA(settings.DimoAuthPrivateKey)
	if err != nil {
		return nil, err
	}

	return &DimoAuthService{
		authURL:    settings.DimoAuthURL,
		clientID:   settings.DimoAuthClientID,
		domain:     settings.DimoAuthDomain.String(),
		privateKey: ecdsaPrivateKey,
		logger:     logger,
	}, nil
}

func (a *DimoAuthService) GetToken() *jwt.Token {
	a.m.Lock()
	defer a.m.Unlock()
	a.validateCurrentToken()
	if a.token == nil {
		token, err := a.getNewToken()
		if err != nil {
			a.logger.Error().Err(err).Msg("Error getting new token")
		}
		a.token = token
	}

	return a.token
}

func (a *DimoAuthService) validateCurrentToken() {
	a.logger.Debug().Msg("validate current token")
	if a.token == nil {
		a.logger.Debug().Msg("token is nil")
		return
	}

	now := time.Now()
	tokenExpirationTime, err := a.token.Claims.GetExpirationTime()
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get token expiration time")
		a.token = nil
		return
	}

	if tokenExpirationTime.Before(now) {
		a.logger.Debug().Msg("token expired")
		a.token = nil
		return
	}

	a.logger.Debug().Msg("token valid")
}

func (a *DimoAuthService) getNewToken() (*jwt.Token, error) {
	challenge, err := a.getChallenge()
	if err != nil {
		return nil, err
	}

	signature, err := a.signChallenge(challenge)
	if err != nil {
		return nil, err
	}

	submitPayload := AuthSubmitChallengePayload{
		ClientID:  a.clientID.String(),
		State:     challenge.State,
		GrantType: "authorization_code",
		Domain:    a.domain,
		Signature: hexutil.Encode(signature),
	}

	challengeResponse, err := a.submitChallenge(submitPayload)
	if err != nil {
		return nil, err
	}

	claims := jwt.MapClaims{}
	token, _, err := jwt.NewParser().ParseUnverified(challengeResponse.AccessToken, &claims)
	if err != nil {
		return nil, err
	}

	return token, nil

}

func (a *DimoAuthService) signChallenge(challenge *AuthChallenge) ([]byte, error) {
	msg := []byte(challenge.Challenge)
	fullMsg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msg), msg)

	hash := crypto.Keccak256Hash([]byte(fullMsg))
	signature, err := crypto.Sign(hash.Bytes(), a.privateKey)
	if err != nil {
		return nil, err
	}
	signature[64] += 27
	return signature, nil
}

func (a *DimoAuthService) getChallenge() (*AuthChallenge, error) {
	hcw, _ := shttp.NewClientWrapper(a.authURL.String(), "", 10*time.Second, nil, true, shttp.WithRetry(3))

	payload := url.Values{}
	payload.Add("client_id", a.clientID.String())
	payload.Add("domain", a.domain)
	payload.Add("scope", "openid email")
	payload.Add("response_type", "code")
	payload.Add("address", a.clientID.String())

	resp, err := hcw.ExecuteRequest("/auth/web3/generate_challenge?"+payload.Encode(), "POST", nil)
	if err != nil {
		a.logger.Err(err).Msg("Failed to send auth challenge request")
		return nil, err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			a.logger.Err(err).Msg("Failed to close response body")
		}
	}(resp.Body)

	if resp.StatusCode != 200 {
		return nil, core.ErrBadRequest
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		a.logger.Err(err).Msgf("Failed to read response body")
		return nil, err
	}

	var decoded = AuthChallenge{}
	if err = json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}

	return &decoded, nil
}

func (a *DimoAuthService) submitChallenge(challenge AuthSubmitChallengePayload) (*AuthSubmitChallengeResponse, error) {
	h := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		//"Accept":       "application/json",
	}
	hcw, _ := shttp.NewClientWrapper(a.authURL.String(), "", 10*time.Second, h, false, shttp.WithRetry(3))

	payload := url.Values{}
	payload.Add("client_id", challenge.ClientID)
	payload.Add("state", challenge.State)
	payload.Add("grant_type", challenge.GrantType)
	payload.Add("domain", challenge.Domain)
	payload.Add("signature", challenge.Signature)

	payloadBytes := []byte(payload.Encode())

	resp, err := hcw.ExecuteRequest("/auth/web3/submit_challenge", "POST", payloadBytes)
	if err != nil {
		a.logger.Err(err).Msg("Failed to submit auth challenge")
		return nil, err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			a.logger.Err(err).Msg("Failed to close response body")
		}
	}(resp.Body)

	if resp.StatusCode != 200 {
		return nil, core.ErrBadRequest
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		a.logger.Err(err).Msgf("Failed to read response body")
		return nil, err
	}

	var decoded = AuthSubmitChallengeResponse{}
	if err = json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}

	return &decoded, nil
}

type AuthRequestChallengePayload struct {
	ClientID     string `json:"client_id"`
	Domain       string `json:"domain"`
	Scope        string `json:"scope"`
	ResponseType string `json:"response_type"`
	Address      string `json:"address"`
}

type AuthChallenge struct {
	State     string `json:"state"`
	Challenge string `json:"challenge"`
}

type AuthSubmitChallengePayload struct {
	ClientID  string `json:"client_id"`
	Domain    string `json:"domain"`
	GrantType string `json:"grant_type"`
	State     string `json:"state"`
	Signature string `json:"signature"`
}

type AuthSubmitChallengeResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
}
