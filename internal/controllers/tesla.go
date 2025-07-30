package controllers

import (
	"context"
	"fmt"
	"github.com/DIMO-Network/shared/pkg/db"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/DIMO-Network/shared/pkg/logfields"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/helpers"
	"github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	mod "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/ethereum/go-ethereum/common"
	"github.com/friendsofgo/errors"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
)

type CredStore interface {
	Store(ctx context.Context, user common.Address, cred *service.Credential) error
	Retrieve(_ context.Context, user common.Address) (*service.Credential, error)
}

type TeslaController struct {
	settings       *config.Settings
	logger         *zerolog.Logger
	fleetAPISvc    service.TeslaFleetAPIService
	ddSvc          service.DeviceDefinitionsAPIService
	identitySvc    service.IdentityAPIService
	requiredScopes []string
	store          CredStore
	Dbc            func() *db.ReaderWriter
}

func NewTeslaController(settings *config.Settings, logger *zerolog.Logger, teslaFleetAPISvc service.TeslaFleetAPIService, ddSvc service.DeviceDefinitionsAPIService, identitySvc service.IdentityAPIService, store CredStore, Dbc func() *db.ReaderWriter) *TeslaController {
	var requiredScopes []string
	if settings.TeslaRequiredScopes != "" {
		requiredScopes = strings.Split(settings.TeslaRequiredScopes, ",")
	}

	return &TeslaController{
		settings:       settings,
		logger:         logger,
		fleetAPISvc:    teslaFleetAPISvc,
		ddSvc:          ddSvc,
		identitySvc:    identitySvc,
		requiredScopes: requiredScopes,
		store:          store,
		Dbc:            Dbc,
	}
}

// GetSettings
// @Summary Get tesla-related configuration parameters
// @Description Get config params for frontend app
// @Tags Settings
// @Produce json
// @Success 200
// @Security     BearerAuth
// @Router /v1/tesla/settings [get]
func (t *TeslaController) GetSettings(c *fiber.Ctx) error {
	payload := TeslaSettingsResponse{
		TeslaClientID:    t.settings.TeslaClientID,
		TeslaAuthURL:     t.settings.TeslaAuthURL,
		TeslaRedirectURI: t.settings.TeslaRedirectURL,
	}
	return c.JSON(payload)
}

type TeslaSettingsResponse struct {
	TeslaAuthURL     string `json:"authUrl"`
	TeslaClientID    string `json:"clientId"`
	TeslaRedirectURI string `json:"redirectUri"`
}

type partialTeslaClaims struct {
	jwt.RegisteredClaims
	Scopes []string `json:"scp"`

	// For debugging.
	OUCode string `json:"ou_code"`
}

var teslaCodeFailureCount = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "tesla_oracle",
		Subsystem: "tesla",
		Name:      "code_exchange_failures_total",
		Help:      "Known strains of failure during Tesla authorization code exchange and ensuing vehicle display.",
	},
	[]string{"type"},
)

// TelemetrySubscribe godoc
// @Summary     Subscribe vehicle for Tesla Telemetry Data
// @Description Subscribe vehicle for Telemetry Data.
// @Tags        tesla,subsribe
// @Produce     json
// @Security    BearerAuth
// @Router /v1/tesla/telemetry/subscribe [post]
func (tc *TeslaController) TelemetrySubscribe(c *fiber.Ctx) error {
	// Logger setup
	logger := helpers.GetLogger(c, tc.logger).With().
		Str("Name", "Telemetry/Subscribe").
		Logger()

	logger.Info().Msg("Received telemetry subscribe request.")

	// Fetch wallet address
	walletAddress := helpers.GetWallet(c)

	// Retrieve Tesla OAuth credentials from the store
	cred, err := tc.store.Retrieve(c.Context(), walletAddress)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			logger.Warn().Msg("Tesla credentials not found in store.")
			return fiber.NewError(fiber.StatusUnauthorized, "Tesla credentials not found. Please authenticate.")
		}
		logger.Err(err).Msg("Failed to retrieve Tesla credentials from store.")
		return fiber.NewError(fiber.StatusInternalServerError, "Internal server error while retrieving Tesla credentials.")
	}

	// Validate access token
	if cred.AccessToken == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "Access token is missing. Please authenticate.")
	}

	// get VIN using the wallet address
	// Call the FindSyntheticDevice function
	device, err := mod.SyntheticDevices(
		mod.SyntheticDeviceWhere.Address.EQ(walletAddress.Bytes()),
	).One(c.Context(), tc.Dbc().Reader)
	if err != nil {
		logger.Err(err).Msg("Failed to find synthetic device.")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to find synthetic device.")
	}

	// Call SubscribeForTelemetryData
	if err := tc.fleetAPISvc.SubscribeForTelemetryData(c.Context(), cred.AccessToken, device.Vin); err != nil {
		logger.Err(err).Msg("Error registering for telemetry")
		var subErr *service.TeslaSubscriptionError
		if errors.As(err, &subErr) {
			switch subErr.Type {
			case service.KeyUnpaired:
				return fiber.NewError(fiber.StatusBadRequest, "Virtual key not paired with vehicle.")
			case service.UnsupportedVehicle:
				return fiber.NewError(fiber.StatusBadRequest, "Pre-2021 Model S and X do not support telemetry.")
			case service.UnsupportedFirmware:
				return fiber.NewError(fiber.StatusBadRequest, "Vehicle firmware version is earlier than 2024.26.")
			}
		}
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to update telemetry configuration.")
	}

	logger.Info().Msg("Successfully subscribed to telemetry.")
	return c.JSON(fiber.Map{"message": "Successfully subscribed to vehicle telemetry."})
}

// UnsubscribeTelemetry godoc
// @Summary     Unsubscribe vehicle from Tesla Telemetry Data
// @Description Unsubscribe vehicle from Telemetry Data using the wallet address to determine the VIN.
// @Tags        tesla,unsubscribe
// @Produce     json
// @Security    BearerAuth
// @Success     200 {object} map[string]string "Successfully unsubscribed from telemetry data"
// @Failure     401 {object} fiber.Error "Unauthorized"
// @Failure     500 {object} fiber.Error "Internal server error"
// @Router      /v1/tesla/telemetry/unsubscribe [delete]
func (t *TeslaController) UnsubscribeTelemetry(c *fiber.Ctx) error {
	// Logger setup
	logger := helpers.GetLogger(c, t.logger).With().
		Str("Name", "Telemetry/Unsubscribe").
		Logger()

	logger.Info().Msg("Received telemetry unsubscribe request.")

	// Fetch wallet address
	walletAddress := helpers.GetWallet(c)

	// Retrieve Tesla OAuth credentials from the store
	cred, err := t.store.Retrieve(c.Context(), walletAddress)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			logger.Warn().Msg("Tesla credentials not found in store.")
			return fiber.NewError(fiber.StatusUnauthorized, "Tesla credentials not found. Please authenticate.")
		}
		logger.Err(err).Msg("Failed to retrieve Tesla credentials from store.")
		return fiber.NewError(fiber.StatusInternalServerError, "Internal server error while retrieving Tesla credentials.")
	}

	// Validate access token
	if cred.AccessToken == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "Access token is missing. Please authenticate.")
	}

	// Retrieve VIN using the wallet address
	device, err := mod.SyntheticDevices(
		mod.SyntheticDeviceWhere.Address.EQ(walletAddress.Bytes()),
	).One(c.Context(), t.Dbc().Reader)
	if err != nil {
		logger.Err(err).Msg("Failed to find synthetic device.")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to find synthetic device.")
	}

	// Call the UnSubscribeFromTelemetryData function
	err = t.fleetAPISvc.UnSubscribeFromTelemetryData(c.Context(), cred.AccessToken, device.Vin)
	if err != nil {
		logger.Err(err).Str("vin", device.Vin).Msg("Failed to unsubscribe from telemetry data")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to unsubscribe from telemetry data")
	}

	logger.Info().Msg("Successfully unsubscribed from telemetry.")
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Successfully unsubscribed from telemetry data",
	})
}

func (t *TeslaController) ListVehicles(c *fiber.Ctx) error {
	walletAddress := helpers.GetWallet(c)
	logger := helpers.GetLogger(c, t.logger)

	var reqBody CompleteOAuthExchangeRequest
	if err := c.BodyParser(&reqBody); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Couldn't parse JSON request body.")
	}

	if reqBody.AuthorizationCode == "" {
		return fiber.NewError(fiber.StatusBadRequest, "No authorization code provided.")
	}
	if reqBody.RedirectURI == "" {
		return fiber.NewError(fiber.StatusBadRequest, "No redirect URI provided.")
	}

	teslaAuth, err := t.fleetAPISvc.CompleteTeslaAuthCodeExchange(c.Context(), reqBody.AuthorizationCode, reqBody.RedirectURI)
	if err != nil {
		if errors.Is(err, service.ErrInvalidAuthCode) {
			teslaCodeFailureCount.WithLabelValues("auth_code").Inc()
			return fiber.NewError(fiber.StatusBadRequest, "Authorization code invalid, expired, or revoked. Retry login.")
		}
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get tesla authCode:"+err.Error())
	}

	if teslaAuth.RefreshToken == "" {
		return fiber.NewError(fiber.StatusBadRequest, "Code exchange did not return a refresh token. Make sure you've granted offline_access.")
	}

	var claims partialTeslaClaims
	_, _, err = jwt.NewParser().ParseUnverified(teslaAuth.AccessToken, &claims)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Code exchange returned an unparseable access token.")
	}

	var missingScopes []string
	for _, scope := range t.requiredScopes {
		if !slices.Contains(claims.Scopes, scope) {
			missingScopes = append(missingScopes, scope)
		}
	}

	if len(missingScopes) != 0 {
		return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("Missing scopes %s.", strings.Join(missingScopes, ", ")))
	}

	// Save tesla oauth credentials in cache
	if err := t.store.Store(c.Context(), walletAddress, &service.Credential{
		AccessToken:  teslaAuth.AccessToken,
		RefreshToken: teslaAuth.RefreshToken,
		Expiry:       teslaAuth.Expiry,
	}); err != nil {
		return fmt.Errorf("error persisting credentials: %w", err)
	}

	vehicles, err := t.fleetAPISvc.GetVehicles(c.Context(), teslaAuth.AccessToken)
	if err != nil {
		logger.Err(err).Str("subject", claims.Subject).Str("ouCode", claims.OUCode).Interface("audience", claims.Audience).Msg("Error retrieving vehicles.")
		if errors.Is(err, service.ErrWrongRegion) {
			teslaCodeFailureCount.WithLabelValues("wrong_region").Inc()
			return fiber.NewError(fiber.StatusInternalServerError, "Region detection failed. Waiting on a fix from Tesla.")
		}
		return fiber.NewError(fiber.StatusInternalServerError, "Couldn't fetch vehicles from Tesla.")
	}

	decodeStart := time.Now()
	response := make([]TeslaVehicle, 0, len(vehicles))
	for _, v := range vehicles {
		ddRes, err := t.decodeTeslaVIN(v.VIN)
		if err != nil {
			teslaCodeFailureCount.WithLabelValues("vin_decode").Inc()
			logger.Err(err).Str("vin", v.VIN).Msg("Failed to decode Tesla VIN.")
			return fiber.NewError(fiber.StatusFailedDependency, "An error occurred completing tesla authorization")
		}

		response = append(response, TeslaVehicle{
			ExternalID: strconv.Itoa(v.ID),
			VIN:        v.VIN,
			Definition: DeviceDefinition{
				Make:               ddRes.Manufacturer.Name,
				Model:              ddRes.Model,
				Year:               ddRes.Year,
				DeviceDefinitionID: ddRes.DeviceDefinitionID,
			},
		})
	}
	logger.Info().Msgf("Took %s to \"decode\" %d Tesla VINs.", time.Since(decodeStart), len(vehicles))

	vehicleResp := &CompleteOAuthExchangeResponseWrapper{
		Vehicles: response,
	}

	return c.JSON(vehicleResp)
}

// CompleteOAuthExchangeRequest request object for completing tesla OAuth
type CompleteOAuthExchangeRequest struct {
	AuthorizationCode string `json:"authorizationCode"`
	RedirectURI       string `json:"redirectUri"`
}

type CompleteOAuthExchangeResponseWrapper struct {
	Vehicles []TeslaVehicle `json:"vehicles"`
}

type TeslaVehicle struct {
	ExternalID string           `json:"externalId"`
	VIN        string           `json:"vin"`
	Definition DeviceDefinition `json:"definition"`
}

type DeviceDefinition struct {
	Make               string `json:"make"`
	Model              string `json:"model"`
	Year               int    `json:"year"`
	DeviceDefinitionID string `json:"id"`
}

func (t *TeslaController) decodeTeslaVIN(vin string) (*models.DeviceDefinition, error) {
	decodeVIN, err := t.ddSvc.DecodeVin(vin, "USA")
	if err != nil {
		return nil, err
	}

	dd, err := t.getOrWaitForDeviceDefinition(decodeVIN.DeviceDefinitionID)
	if err != nil {
		return nil, err
	}

	return dd, nil
}

func (t *TeslaController) getOrWaitForDeviceDefinition(deviceDefinitionID string) (*models.DeviceDefinition, error) {
	t.logger.Debug().Str(logfields.DefinitionID, deviceDefinitionID).Msg("Waiting for device definition")
	for i := 0; i < 12; i++ {
		definition, err := t.identitySvc.FetchDeviceDefinitionByID(deviceDefinitionID)
		if err != nil || definition == nil || definition.DeviceDefinitionID == "" {
			time.Sleep(5 * time.Second)
			t.logger.Debug().Str(logfields.DefinitionID, deviceDefinitionID).Msgf("Still waiting, retry %d", i+1)
			continue
		}
		return definition, nil
	}

	return nil, errors.New("device definition not found")
}
