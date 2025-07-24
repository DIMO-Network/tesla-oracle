package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"time"

	shttp "github.com/DIMO-Network/shared/pkg/http"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/rs/zerolog"
)

type DeviceDefinitionsAPIService interface {
	DecodeVin(vin, countryCode string) (*DecodeVinResponse, error)
}

type deviceDefinitionsAPIService struct {
	baseURL url.URL
	logger  *zerolog.Logger
	auth    *DimoAuthService
}

func NewDeviceDefinitionsAPIService(logger *zerolog.Logger, settings *config.Settings) DeviceDefinitionsAPIService {
	auth, err := NewDimoAuthService(logger, settings)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create Dimo Auth service")
		return nil
	}

	return &deviceDefinitionsAPIService{
		baseURL: settings.DeviceDefinitionsAPIEndpoint,
		logger:  logger,
		auth:    auth,
	}
}

type DecodeVinPayload struct {
	CountryCode string `json:"countryCode"`
	Vin         string `json:"vin"`
}

type DecodeVinResponse struct {
	DeviceDefinitionID string `json:"deviceDefinitionId"`
	NewTransactionHash string `json:"newTransactionHash"`
}

func (d *deviceDefinitionsAPIService) DecodeVin(vin, countryCode string) (*DecodeVinResponse, error) {
	token := d.auth.GetToken()
	if token == nil {
		d.logger.Error().Msg("Failed to get token")
		return nil, errors.New("failed to get token")
	}

	h := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", token.Raw),
	}
	hcw, _ := shttp.NewClientWrapper(d.baseURL.String(), "", 10*time.Second, h, true, shttp.WithRetry(3))

	payload := DecodeVinPayload{
		CountryCode: countryCode,
		Vin:         vin,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	resp, err := hcw.ExecuteRequest("/device-definitions/decode-vin", "POST", payloadBytes)
	if err != nil {
		d.logger.Err(err).Msg("Failed to send DecodeVIN POST request")
		return nil, err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			d.logger.Err(err).Msg("Failed to close response body")
		}
	}(resp.Body)

	if resp.StatusCode != 200 {
		return nil, ErrBadRequest
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		d.logger.Err(err).Msgf("Failed to read response body")
		return nil, err
	}

	var decoded = DecodeVinResponse{}
	if err = json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}

	return &decoded, nil
}
