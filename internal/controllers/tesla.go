package controllers

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/shared/pkg/logfields"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/helpers"
	"github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/DIMO-Network/tesla-oracle/internal/onboarding"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/aarondl/null/v8"
	"github.com/ethereum/go-ethereum/common"
	"github.com/friendsofgo/errors"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
)

type CredStore interface {
	Store(ctx context.Context, user common.Address, cred *service.Credential) error
	Retrieve(_ context.Context, user common.Address) (*service.Credential, error)
	RetrieveAndDelete(_ context.Context, user common.Address) (*service.Credential, error)
	RetrieveWithTokensEncrypted(_ context.Context, user common.Address) (*service.Credential, error)
	EncryptTokens(cred *service.Credential) (*service.Credential, error)
}

type TeslaController struct {
	settings       *config.Settings
	logger         *zerolog.Logger
	fleetAPISvc    service.TeslaFleetAPIService
	ddSvc          service.DeviceDefinitionsAPIService
	identitySvc    service.IdentityAPIService
	requiredScopes []string
	credStore      CredStore
	onboarding     *service.OnboardingService
	pdb            *db.Store
	devicesService service.DevicesGRPCService
	teslaService   service.TeslaService
}

func NewTeslaController(settings *config.Settings, logger *zerolog.Logger, teslaFleetAPISvc service.TeslaFleetAPIService, ddSvc service.DeviceDefinitionsAPIService, identitySvc service.IdentityAPIService, store CredStore, onboardingSvc *service.OnboardingService, teslaService service.TeslaService, pdb *db.Store) *TeslaController {
	var requiredScopes []string
	if settings.TeslaRequiredScopes != "" {
		requiredScopes = strings.Split(settings.TeslaRequiredScopes, ",")
	}

	var devicesService service.DevicesGRPCService
	var err error
	if !settings.DisableDevicesGRPC {
		devicesService, err = service.NewDevicesGRPCService(settings, logger)
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to initialize DevicesGRPCService")
		}
	} else {
		logger.Warn().Msgf("Devices GRPC is DISABLED")
	}

	return &TeslaController{
		settings:       settings,
		logger:         logger,
		fleetAPISvc:    teslaFleetAPISvc,
		ddSvc:          ddSvc,
		identitySvc:    identitySvc,
		requiredScopes: requiredScopes,
		credStore:      store,
		onboarding:     onboardingSvc,
		pdb:            pdb,
		devicesService: devicesService,
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
// @Tags        tesla,subscribe
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
	if walletAddress != tc.settings.MobileAppDevLicense {
		subscribeTelemetryFailureCount.Inc()
		return fiber.NewError(fiber.StatusUnauthorized, fmt.Sprintf("Dev license %s is not allowed to subscribe to telemetry.", walletAddress.Hex()))
	}
	sd, err := tc.teslaService.GetByVehicleTokenID(c.Context(), tc.logger, tc.pdb, tokenID)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Failed to get vehicle by vehicle token id.")
	}

	err = tc.startStreamingOrPolling(c, sd, logger, tokenID)
	if err != nil {
		subscribeTelemetryFailureCount.Inc()
		return err
	}

	err = tc.teslaService.UpdateSubscriptionStatus(c.Context(), sd, "active")
	if err != nil {
		logger.Err(err).Msg("Failed to update subscription status.")
		subscribeTelemetryFailureCount.Inc()
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to update subscription status.")
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
// @Tags        tesla,start
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

	// Validate vehicle ownership
	//walletAddress := helpers.GetWallet(c)
	//err = tc.validateVehicleOwnership(tokenID, walletAddress)
	//if err != nil {
	//	return err
	//}

	// Fetch synthetic device
	sd, err := tc.teslaService.GetByVehicleTokenID(c.Context(), tc.logger, tc.pdb, tokenID)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Failed to get vehicle by token ID.")
	}

	// Start streaming or polling
	if err := tc.startStreamingOrPolling(c, sd, logger, tokenID); err != nil {
		return err
	}

	logger.Info().Msgf("Successfully started data flow for vehicle: %d.", tokenID)
	return c.JSON(fiber.Map{"message": "Successfully started data flow for vehicle."})
}

// UnsubscribeTelemetry godoc
// @Summary     Unsubscribe vehicle from Tesla Telemetry Data
// @Description Unsubscribes a vehicle from telemetry data using the provided vehicle token ID.
// @Tags        tesla,unsubscribe
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
	if walletAddress != tc.settings.MobileAppDevLicense {
		unsubscribeTelemetryFailureCount.Inc()
		return fiber.NewError(fiber.StatusUnauthorized, fmt.Sprintf("Dev license %s is not allowed to unsubscribe from telemetry.", walletAddress.Hex()))
	}

	partnersTokenResp, err := tc.fleetAPISvc.GetPartnersToken(c.Context())
	if err != nil {
		logger.Err(err).Msg("Failed to get partners token.")
		unsubscribeTelemetryFailureCount.Inc()
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to get partners token.")
	}

	if partnersTokenResp.AccessToken == "" {
		unsubscribeTelemetryFailureCount.Inc()
		return fiber.NewError(fiber.StatusInternalServerError, "Partners token response did not contain an access token.")
	}

	vehicle, err := tc.fetchVehicle(tokenID)
	if err != nil {
		unsubscribeTelemetryFailureCount.Inc()
		return err
	}

	device, err := dbmodels.SyntheticDevices(
		dbmodels.SyntheticDeviceWhere.Address.EQ(common.HexToAddress(vehicle.SyntheticDevice.Address).Bytes())).One(c.Context(), tc.pdb.DBS().Reader)
	if err != nil {
		logger.Err(err).Msg("Failed to find synthetic device.")
		unsubscribeTelemetryFailureCount.Inc()
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to find synthetic device.")
	}

	err = tc.fleetAPISvc.UnSubscribeFromTelemetryData(c.Context(), partnersTokenResp.AccessToken, device.Vin)
	if err != nil {
		logger.Err(err).Str("vin", device.Vin).Msg("Failed to unsubscribe from telemetry data")
		unsubscribeTelemetryFailureCount.Inc()
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to unsubscribe from telemetry data")
	}

	stopErr := tc.devicesService.StopTeslaTask(c.Context(), vehicle.TokenID)
	if stopErr != nil {
		logger.Warn().Err(stopErr).Msg("Failed to stop Tesla task for synthetic device.")
	}

	err = tc.teslaService.UpdateSubscriptionStatus(c.Context(), device, "inactive")
	if err != nil {
		logger.Err(err).Msg("Failed to update subscription status.")
		unsubscribeTelemetryFailureCount.Inc()
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to update subscription status.")
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
// @Tags        tesla,vehicles
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

	// Save tesla oauth credentials in cache
	if err := tc.credStore.Store(c.Context(), walletAddress, &service.Credential{
		AccessToken:   teslaAuth.AccessToken,
		RefreshToken:  teslaAuth.RefreshToken,
		AccessExpiry:  teslaAuth.Expiry,
		RefreshExpiry: time.Now().AddDate(0, 3, 0),
	}); err != nil {
		return fmt.Errorf("error persisting credentials: %w", err)
	}

	vehicles, err := tc.fleetAPISvc.GetVehicles(c.Context(), teslaAuth.AccessToken)
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
		ddRes, err := tc.decodeTeslaVIN(v.VIN)
		if err != nil {
			teslaCodeFailureCount.WithLabelValues("vin_decode").Inc()
			logger.Err(err).Str("vin", v.VIN).Msg("Failed to decode Tesla VIN.")
			return fiber.NewError(fiber.StatusFailedDependency, "An error occurred completing tesla authorization")
		}

		record, err := tc.onboarding.GetVehicleByVin(c.Context(), v.VIN)
		if err != nil {
			if !errors.Is(err, service.ErrVehicleNotFound) {
				logger.Err(err).Str("vin", v.VIN).Msg("Failed to fetch record.")
			}
		}

		if record == nil {
			err = tc.onboarding.InsertVinToDB(c.Context(), &dbmodels.Onboarding{
				Vin:                v.VIN,
				DeviceDefinitionID: null.String{String: ddRes.DeviceDefinitionID, Valid: true},
				OnboardingStatus:   onboarding.OnboardingStatusVendorValidationSuccess,
				ExternalID:         null.String{String: strconv.Itoa(v.ID), Valid: true},
			})

			if err != nil {
				return fiber.NewError(fiber.StatusInternalServerError, "Failed to create onboarding record.")
			}
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

// GetVirtualKeyStatus godoc
// @Summary     Get virtual key status
// @Description Gets information about Tesla virtual key.
// @Tags        tesla,virtual-key
// @Accept      json
// @Produce     json
// @Param       vin	query string true "Vehicle VIN"
// @Security    BearerAuth
// @Success     200 {object} controllers.VirtualKeyStatusResponse
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

	teslaAuth, err := tc.credStore.Retrieve(c.Context(), walletAddress)
	if err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	}

	fleetStatus, err := tc.fleetAPISvc.VirtualKeyConnectionStatus(c.Context(), teslaAuth.AccessToken, params.VIN)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error checking fleet status.")
	}

	fleetTelemetryCapable := service.IsFleetTelemetryCapable(fleetStatus)

	var response = VirtualKeyStatusResponse{}
	response.Added = fleetStatus.KeyPaired
	if !fleetTelemetryCapable {
		response.Status = Incapable
	} else if fleetStatus.KeyPaired {
		response.Status = Paired
	} else {
		response.Status = Unpaired
	}

	return c.JSON(response)
}

// GetStatus godoc
// @Summary     Get vehicle status
// @Description Get vehicle status and determines the next action for a Tesla vehicle based on its fleet status, including telemetry compatibility, virtual key pairing, firmware version, and streaming toggle settings. Provides appropriate instructions or actions for the user to enable telemetry or resolve issues.
// @Tags        tesla,fleet
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
	sd, err := tc.teslaService.GetByVehicleTokenID(c.Context(), tc.logger, tc.pdb, tokenID)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Failed to get vehicle by vehicle token id.")
	}

	// check if the user owns the vehicle
	//walletAddress := helpers.GetWallet(c)
	//err = tc.validateVehicleOwnership(tokenID, walletAddress)
	//if err != nil {
	//	return err
	//}

	// check if we have access token
	if sd == nil || sd.AccessToken.String == "" || sd.RefreshToken.String == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "No credentials found for vehicle. Please reauthenticate.")
	}

	accessToken, err := tc.getOrRefreshAccessToken(c, sd, *tc.logger)
	if err != nil {
		return err
	}

	// get status and decide on action
	statusDecision, err := tc.decideOnAction(c, sd, accessToken, tokenID)
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

// fetchVehicle retrieves a vehicle from identity-api by its token ID.
func (tc *TeslaController) fetchVehicle(vehicleTokenId int64) (*models.Vehicle, error) {
	vehicle, vehErr := tc.identitySvc.FetchVehicleByTokenID(vehicleTokenId)
	if vehErr != nil {
		tc.logger.Err(vehErr).Msg("Failed to fetch vehicle by token ID.")
		return nil, fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch vehicle information.")
	}

	if vehicle == nil || vehicle.Owner == "" || vehicle.SyntheticDevice.Address == "" {
		tc.logger.Warn().Msg("Vehicle not found or owner information or synthetic device address is missing.")
		return nil, fiber.NewError(fiber.StatusNotFound, "Vehicle not found or owner information or synthetic device address is missing.")
	}
	return vehicle, nil
}

func (tc *TeslaController) decodeTeslaVIN(vin string) (*models.DeviceDefinition, error) {
	decodeVIN, err := tc.ddSvc.DecodeVin(vin, "USA")
	if err != nil {
		return nil, err
	}

	dd, err := tc.getOrWaitForDeviceDefinition(decodeVIN.DeviceDefinitionID)
	if err != nil {
		return nil, err
	}

	return dd, nil
}

func (tc *TeslaController) getOrWaitForDeviceDefinition(deviceDefinitionID string) (*models.DeviceDefinition, error) {
	tc.logger.Debug().Str(logfields.DefinitionID, deviceDefinitionID).Msg("Waiting for device definition")
	for i := 0; i < 12; i++ {
		definition, err := tc.identitySvc.FetchDeviceDefinitionByID(deviceDefinitionID)
		if err != nil || definition == nil || definition.DeviceDefinitionID == "" {
			time.Sleep(5 * time.Second)
			tc.logger.Debug().Str(logfields.DefinitionID, deviceDefinitionID).Msgf("Still waiting, retry %d", i+1)
			continue
		}
		return definition, nil
	}

	return nil, errors.New("device definition not found")
}

// getOrRefreshAccessToken checks if the access token for the given synthetic device has expired.
// If the access token is expired and the refresh token is still valid, it attempts to refresh the access token.
// If the refresh token is expired, it returns an unauthorized error.
func (tc *TeslaController) getOrRefreshAccessToken(c *fiber.Ctx, sd *dbmodels.SyntheticDevice, logger zerolog.Logger) (string, error) {
	accessToken, err := tc.teslaService.Cipher.Decrypt(sd.AccessToken.String)
	if err != nil {
		return "", fiber.NewError(fiber.StatusInternalServerError, "Failed to decrypt access token.")
	}

	if !sd.AccessExpiresAt.IsZero() && time.Now().After(sd.AccessExpiresAt.Time) {
		refreshToken, err := tc.teslaService.Cipher.Decrypt(sd.RefreshToken.String)
		if err != nil {
			return "", fiber.NewError(fiber.StatusInternalServerError, "Failed to decrypt access token.")
		}
		if !sd.RefreshExpiresAt.IsZero() && time.Now().Before(sd.RefreshExpiresAt.Time) {
			tokens, err := tc.fleetAPISvc.RefreshToken(c.Context(), refreshToken)
			if err != nil {
				return "", fiber.NewError(fiber.StatusInternalServerError, "Failed to refresh access token.")
			}
			// TODO verify if ExpiresIn in seconds or milliseconds
			expiryTime := time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
			creds := service.Credential{
				AccessToken:   tokens.AccessToken,
				RefreshToken:  tokens.RefreshToken,
				AccessExpiry:  expiryTime,
				RefreshExpiry: time.Now().AddDate(0, 3, 0),
			}
			errUpdate := tc.teslaService.UpdateCreds(c.Context(), sd, &creds)
			if errUpdate != nil {
				logger.Warn().Err(errUpdate).Msg("Failed to update credentials after refresh.")
			}
			return tokens.AccessToken, nil
		} else {
			return "", fiber.NewError(fiber.StatusUnauthorized, "Refresh token has expired. Please reauthenticate.")
		}
	}
	return accessToken, nil
}

// startStreamingOrPolling determines whether to start streaming telemetry data or polling for a Tesla vehicle.
// It checks if the vehicle has valid credentials, refreshes the access token if necessary, and decides the next action.
func (tc *TeslaController) startStreamingOrPolling(c *fiber.Ctx, sd *dbmodels.SyntheticDevice, logger zerolog.Logger, tokenID int64) error {
	// check if we have access token
	if sd == nil || sd.AccessToken.String == "" || sd.RefreshToken.String == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "No credentials found for vehicle. Please reauthenticate.")
	}

	accessToken, err := tc.getOrRefreshAccessToken(c, sd, logger)
	if err != nil {
		return err
	}

	resp, err := tc.decideOnAction(c, sd, accessToken, tokenID)
	if err != nil {
		return err
	}

	// call appropriate action
	switch resp.Action {
	case models.ActionSetTelemetryConfig:
		subStatus, err := tc.fleetAPISvc.GetTelemetrySubscriptionStatus(c.Context(), accessToken, sd.Vin)
		if err != nil {
			logger.Err(err).Msg("Error checking telemetry subscription status")
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to check telemetry subscription status.")
		}
		if subStatus.LimitReached {
			return fiber.NewError(fiber.StatusConflict, "Telemetry subscription limit reached. Vehicle has reached max supported applications and new fleet telemetry requests cannot be added to the vehicle.")
		}

		if err := tc.fleetAPISvc.SubscribeForTelemetryData(c.Context(), accessToken, sd.Vin); err != nil {
			logger.Err(err).Msg("Error registering for telemetry")
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to update telemetry configuration.")
		}

	case models.ActionStartPolling:
		startErr := tc.devicesService.StartTeslaTask(c.Context(), tokenID)
		if startErr != nil {
			logger.Warn().Err(startErr).Msg("Failed to start Tesla task for synthetic device.")
		}

	default:
		return fiber.NewError(fiber.StatusConflict, "Vehicle is not ready for telemetry subscription. Call GetStatus endpoint to determine next steps.")
	}
	return nil
}

// decideOnAction determines the next action for a Tesla vehicle based on its fleet status.
// It retrieves the vehicle's connection status and evaluates the appropriate action using a decision tree.
func (tc *TeslaController) decideOnAction(c *fiber.Ctx, sd *dbmodels.SyntheticDevice, accessToken string, tokenID int64) (*models.StatusDecision, error) {
	// get vehicle status
	connectionStatus, err := tc.fleetAPISvc.VirtualKeyConnectionStatus(c.Context(), accessToken, sd.Vin)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusInternalServerError, "Error checking fleet status.")
	}

	// determine action based on status
	resp, err := service.DecisionTreeAction(connectionStatus, tokenID)
	if err != nil {
		tc.logger.Err(err)
		return nil, fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("Error determining fleet action: %s", err.Error()))
	}
	return resp, nil
}

// validateVehicleOwnership checks if the vehicle belongs to the authenticated user.
func (tc *TeslaController) validateVehicleOwnership(tokenID int64, walletAddress common.Address) error {
	vehicle, err := tc.fetchVehicle(tokenID)
	if err != nil {
		return err
	}

	if vehicle == nil || vehicle.Owner != walletAddress.Hex() {
		return fiber.NewError(fiber.StatusUnauthorized, "Vehicle does not belong to the authenticated user.")
	}

	return nil
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
