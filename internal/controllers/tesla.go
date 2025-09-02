package controllers

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/helpers"
	"github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	"github.com/friendsofgo/errors"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
)

type TeslaController struct {
	settings       *config.Settings
	logger         *zerolog.Logger
	fleetAPISvc    service.TeslaFleetAPIService
	ddSvc          service.DeviceDefinitionsAPIService
	identitySvc    service.IdentityAPIService
	requiredScopes []string
	repositories   *repository.Repositories
	onboarding     *service.OnboardingService
	teslaService   *service.TeslaService
}

func NewTeslaController(settings *config.Settings, logger *zerolog.Logger, teslaFleetAPISvc service.TeslaFleetAPIService, ddSvc service.DeviceDefinitionsAPIService, identitySvc service.IdentityAPIService, repositories *repository.Repositories, onboardingSvc *service.OnboardingService, teslaService *service.TeslaService) *TeslaController {
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
		repositories:   repositories,
		onboarding:     onboardingSvc,
		teslaService:   teslaService,
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
func (tc *TeslaController) GetSettings(c *fiber.Ctx) error {
	payload := TeslaSettingsResponse{
		TeslaClientID:    tc.settings.TeslaClientID,
		TeslaAuthURL:     tc.settings.TeslaAuthURL.String(),
		TeslaRedirectURI: tc.settings.TeslaRedirectURL.String(),
		VirtualKeyURL:    tc.settings.TeslaVirtualKeyURL.String(),
	}
	return c.JSON(payload)
}

type TeslaSettingsResponse struct {
	TeslaAuthURL     string `json:"authUrl"`
	TeslaClientID    string `json:"clientId"`
	TeslaRedirectURI string `json:"redirectUri"`
	VirtualKeyURL    string `json:"virtualKeyUrl"`
}

type partialTeslaClaims struct {
	jwt.RegisteredClaims
	Scopes []string `json:"scp"`

	// For debugging.
	OUCode string `json:"ou_code"`
}

// TelemetrySubscribe godoc
// @Summary     Subscribe vehicle for Tesla Telemetry Data
// @Description Subscribes a vehicle for telemetry data using the provided vehicle token ID in the request path.
//
//	Validates the developer license, retrieves the synthetic device, and initiates telemetry streaming
//	or polling based on the vehicle's status. Updates the subscription status to "active" upon success.
//
// @Tags        telemetry
// @Accept      json
// @Produce     json
// @Param       vehicleTokenId path string true "Vehicle token ID that must be set in the request path to fetch vehicle details"
// @Security    BearerAuth
// @Success     200 {object} map[string]string "Successfully subscribed to vehicle telemetry."
// @Failure     400 {object} fiber.Error "Bad Request"
// @Failure     401 {object} fiber.Error "Unauthorized or invalid developer license."
// @Failure     404 {object} fiber.Error "Vehicle not found or failed to get vehicle by VIN."
// @Failure     409 {object} fiber.Error "Vehicle is not ready for telemetry subscription."
// @Failure     500 {object} fiber.Error "Internal server error, including decryption or telemetry subscription failures."
// @Router      /v1/tesla/telemetry/subscribe/{vehicleTokenId} [post]
func (tc *TeslaController) TelemetrySubscribe(c *fiber.Ctx) error {
	logger := helpers.GetLogger(c, tc.logger).With().
		Str("Name", "Telemetry/Subscribe").
		Logger()

	tokenID, err := extractVehicleTokenId(c)
	if err != nil {
		subscribeTelemetryFailureCount.Inc()
		return err
	}

	logger.Debug().Msgf("Received telemetry subscribe request for %d.", tokenID)

	walletAddress := helpers.GetWallet(c)
	err = tc.teslaService.SubscribeToTelemetry(c.Context(), tokenID, walletAddress)
	if err != nil {
		subscribeTelemetryFailureCount.Inc()
		return err
	}

	logger.Info().Msgf("Successfully subscribed to telemetry vehicle: %d.", tokenID)
	subscribeTelemetrySuccessCount.Inc()
	return c.JSON(fiber.Map{"message": "Successfully subscribed to vehicle telemetry."})
}

// StartDataFlow godoc
// @Summary     Start data flow for Tesla vehicle
// @Description Initiates the data flow for a Tesla vehicle using the provided vehicle token ID.
//
//	Validates vehicle ownership, checks credentials, and determines the appropriate action
//	(streaming telemetry data or polling) based on the vehicle's status. If the vehicle is not ready
//	for telemetry subscription, it provides instructions to the user to resolve the issue.
//
// @Tags        tesla
// @Accept      json
// @Produce     json
// @Param       vehicleTokenId path string true "Vehicle token ID that must be set in the request path to fetch vehicle details"
// @Security    BearerAuth
// @Success     200 {object} map[string]string "Successfully started data flow for the vehicle."
// @Failure     400 {object} fiber.Error "Bad Request"
// @Failure     401 {object} fiber.Error "Unauthorized or vehicle does not belong to the authenticated user."
// @Failure     404 {object} fiber.Error "Vehicle not found or failed to get vehicle by token ID."
// @Failure     409 {object} fiber.Error "Vehicle is not ready for telemetry subscription. Call GetStatus endpoint to determine next steps."
// @Failure     500 {object} fiber.Error "Internal server error, including decryption or fleet status retrieval failures."
// @Router      /v1/tesla/{vehicleTokenId}/start [post]
func (tc *TeslaController) StartDataFlow(c *fiber.Ctx) error {
	logger := helpers.GetLogger(c, tc.logger).With().
		Str("Name", "Telemetry/Start").
		Logger()

	tokenID, err := extractVehicleTokenId(c)
	if err != nil {
		return err
	}

	logger.Debug().Msgf("Received telemetry start request for %d.", tokenID)

	walletAddress := helpers.GetWallet(c)
	err = tc.teslaService.StartVehicleDataFlow(c.Context(), tokenID, walletAddress)
	if err != nil {
		return err
	}

	logger.Info().Msgf("Successfully started data flow for vehicle: %d.", tokenID)
	return c.JSON(fiber.Map{"message": "Successfully started data flow for vehicle."})
}

// UnsubscribeTelemetry godoc
// @Summary     Unsubscribe vehicle from Tesla Telemetry Data
// @Description Unsubscribes a vehicle from telemetry data using the provided vehicle token ID.
// @Tags        telemetry
// @Accept      json
// @Produce     json
// @Param       vehicleTokenId path string true "OnboardingService Token ID"
// @Security    BearerAuth
// @Success     200 {object} map[string]string "Successfully unsubscribed from telemetry data."
// @Failure     400 {object} fiber.Error "Bad Request"
// @Failure     401 {object} fiber.Error "Unauthorized"
// @Failure     404 {object} fiber.Error "OnboardingService not found or owner information is missing."
// @Failure     500 {object} fiber.Error "Internal server error"
// @Router      /v1/tesla/telemetry/unsubscribe/{vehicleTokenId} [post]
func (tc *TeslaController) UnsubscribeTelemetry(c *fiber.Ctx) error {
	tokenID, err := extractVehicleTokenId(c)
	if err != nil {
		unsubscribeTelemetryFailureCount.Inc()
		return err
	}

	logger := helpers.GetLogger(c, tc.logger).With().
		Str("Name", "Telemetry/Unsubscribe").
		Logger()

	logger.Info().Msgf("Received telemetry unsubscribe request for %d.", tokenID)

	walletAddress := helpers.GetWallet(c)
	err = tc.teslaService.UnsubscribeFromTelemetry(c.Context(), tokenID, walletAddress)
	if err != nil {
		unsubscribeTelemetryFailureCount.Inc()
		return err
	}

	logger.Info().Msgf(`Successfully unsubscribed vehicle %d from telemetry data.`, tokenID)
	unsubscribeTelemetrySuccessCount.Inc()
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Successfully unsubscribed from telemetry data",
	})
}

// ListVehicles godoc
// @Summary     Get user vehicles
// @Description Gets Tesla vehicles owned by the user. Creates initial onboarding records for all of them.
// @Tags        tesla
// @Accept      json
// @Produce     json
// @Param       payload body controllers.CompleteOAuthExchangeRequest true "Authorization details"
// @Security    BearerAuth
// @Success     200 {object} controllers.CompleteOAuthExchangeResponseWrapper
// @Failure     400 {object} fiber.Error "Bad Request"
// @Failure     401 {object} fiber.Error "Unauthorized"
// @Failure     424 {object} fiber.Error "Failed Dependency"
// @Failure     500 {object} fiber.Error "Internal server error"
// @Router      /v1/tesla/vehicles [post]
func (tc *TeslaController) ListVehicles(c *fiber.Ctx) error {
	walletAddress := helpers.GetWallet(c)
	logger := helpers.GetLogger(c, tc.logger)

	teslaAuth, err := tc.getAccessToken(c)
	if err != nil {
		return err
	}

	var claims partialTeslaClaims
	_, _, err = jwt.NewParser().ParseUnverified(teslaAuth.AccessToken, &claims)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Code exchange returned an unparseable access token.")
	}

	var missingScopes []string
	for _, scope := range tc.requiredScopes {
		if !slices.Contains(claims.Scopes, scope) {
			missingScopes = append(missingScopes, scope)
		}
	}

	if len(missingScopes) != 0 {
		return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("Missing scopes %s.", strings.Join(missingScopes, ", ")))
	}

	decodeStart := time.Now()
	response, err := tc.teslaService.CompleteOAuthFlow(c.Context(), walletAddress, teslaAuth)
	if err != nil {
		logger.Err(err).Str("subject", claims.Subject).Str("ouCode", claims.OUCode).Interface("audience", claims.Audience).Msg("Error completing OAuth flow.")
		teslaCodeFailureCount.WithLabelValues("oauth_flow").Inc()
		return err
	}
	logger.Info().Msgf("Took %s to complete OAuth flow and decode %d Tesla VINs.", time.Since(decodeStart), len(response))

	vehicleResp := &CompleteOAuthExchangeResponseWrapper{
		Vehicles: response,
	}

	return c.JSON(vehicleResp)
}

// GetVirtualKeyStatus godoc
// @Summary     Get virtual key status
// @Description Gets information about Tesla virtual key.
// @Tags        tesla
// @Accept      json
// @Produce     json
// @Param       vin	query string true "Vehicle VIN"
// @Security    BearerAuth
// @Success     200 {object} service.VirtualKeyStatusResponse
// @Failure     400 {object} fiber.Error "Bad Request"
// @Failure     401 {object} fiber.Error "Unauthorized"
// @Failure     500 {object} fiber.Error "Internal server error"
// @Router      /v1/tesla/virtual-key [get]
func (tc *TeslaController) GetVirtualKeyStatus(c *fiber.Ctx) error {
	walletAddress := helpers.GetWallet(c)

	var params VinInput
	if err := c.QueryParser(&params); err != nil {
		tc.logger.Err(err).Msg("Failed to parse request URL params")
		return fiber.NewError(fiber.StatusBadRequest, "Failed to parse request URL params")
	}

	response, err := tc.teslaService.GetVirtualKeyStatus(c.Context(), params.VIN, walletAddress)
	if err != nil {
		return err
	}

	return c.JSON(response)
}

// GetStatus godoc
// @Summary     Get vehicle status
// @Description Get vehicle status and determines the next action for a Tesla vehicle based on its fleet status, including telemetry compatibility, virtual key pairing, firmware version, and streaming toggle settings. Provides appropriate instructions or actions for the user to enable telemetry or resolve issues.
// @Tags        tesla
// @Accept      json
// @Produce     json
// @Param       vehicleTokenId path string true "Vehicle token ID that must be set in the request path to fetch vehicle details"
// @Security    BearerAuth
// @Success 200 {object} models.VehicleStatusResponse "Vehicle status details and next action"
// @Failure     400 {object} fiber.Error "Bad Request"
// @Failure     401 {object} fiber.Error "Unauthorized or no credentials found for the vehicle."
// @Failure     404 {object} fiber.Error "Vehicle not found or failed to get vehicle by token ID."
// @Failure     500 {object} fiber.Error "Internal server error, including decryption or fleet status retrieval failures."
// @Router      /v1/tesla/{vehicleTokenId}/status [get]
func (tc *TeslaController) GetStatus(c *fiber.Ctx) error {
	tokenID, err := extractVehicleTokenId(c)
	if err != nil {
		return err
	}

	walletAddress := helpers.GetWallet(c)
	statusDecision, err := tc.teslaService.GetVehicleStatus(c.Context(), tokenID, walletAddress)
	if err != nil {
		return err
	}

	// do not return internal action to client
	resp := &models.VehicleStatusResponse{
		Message: statusDecision.Message,
		Next:    statusDecision.Next,
	}

	return c.JSON(resp)
}

func (tc *TeslaController) getAccessToken(c *fiber.Ctx) (*service.TeslaAuthCodeResponse, error) {
	var reqBody CompleteOAuthExchangeRequest
	if err := c.BodyParser(&reqBody); err != nil {
		tc.logger.Err(err).Msg("Failed to parse request body OR it is empty.")
		return nil, fiber.NewError(fiber.StatusBadRequest, "Failed to parse request body OR it is empty.")
	}

	if reqBody.AuthorizationCode == "" && reqBody.RedirectURI == "" {
		return nil, fiber.NewError(fiber.StatusBadRequest, "Both AuthorizationCode and RedirectURI are missing.")
	}

	if reqBody.AuthorizationCode == "" {
		return nil, fiber.NewError(fiber.StatusBadRequest, "No authorization code provided.")
	}
	if reqBody.RedirectURI == "" {
		return nil, fiber.NewError(fiber.StatusBadRequest, "No redirect URI provided.")
	}

	teslaAuth, err := tc.fleetAPISvc.CompleteTeslaAuthCodeExchange(c.Context(), reqBody.AuthorizationCode, reqBody.RedirectURI)
	if err != nil {
		if errors.Is(err, service.ErrInvalidAuthCode) {
			teslaCodeFailureCount.WithLabelValues("auth_code").Inc()
			return nil, fiber.NewError(fiber.StatusBadRequest, "Authorization code invalid, expired, or revoked. Retry login.")
		}
		return nil, fiber.NewError(fiber.StatusInternalServerError, "failed to get tesla authCode:"+err.Error())
	}

	if teslaAuth.RefreshToken == "" {
		return nil, fiber.NewError(fiber.StatusBadRequest, "Code exchange did not return a refresh token. Make sure you've granted offline_access.")
	}
	return teslaAuth, nil
}

func extractVehicleTokenId(c *fiber.Ctx) (int64, error) {
	vehicleTokenId := c.Params("vehicleTokenId")
	if vehicleTokenId == "" {
		return 0, fiber.NewError(fiber.StatusBadRequest, "VehicleTokenId is required in the request path.")
	}

	tokenID, convErr := helpers.StringToInt64(vehicleTokenId)
	if convErr != nil {
		return 0, fiber.NewError(fiber.StatusBadRequest, "Invalid vehicle token ID format.")
	}
	return tokenID, nil
}
