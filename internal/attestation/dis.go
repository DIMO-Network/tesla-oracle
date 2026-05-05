package attestation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/DIMO-Network/cloudevent"
)

type DISClient struct {
	baseURL    *url.URL
	httpClient *http.Client
	dex        *DexClient
	cache      *TokenCache
}

func NewDISClient(httpClient *http.Client, baseURL *url.URL, dex *DexClient) *DISClient {
	return &DISClient{
		baseURL:    baseURL,
		httpClient: httpClient,
		dex:        dex,
		cache:      &TokenCache{},
	}
}

func (d *DISClient) UploadAttestation(ctx context.Context, attestation *cloudevent.RawEvent) error {
	eventBytes, err := json.Marshal(attestation)
	if err != nil {
		return fmt.Errorf("marshal cloud event: %w", err)
	}

	token, err := d.cache.GetToken(ctx, d.dex)
	if err != nil {
		return fmt.Errorf("get bearer token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.baseURL.String(), bytes.NewReader(eventBytes))
	if err != nil {
		return fmt.Errorf("build DIS request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("DIS request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("DIS status %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}

	return nil
}
