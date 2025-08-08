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
	"github.com/ethereum/go-ethereum/common"
	"github.com/friendsofgo/errors"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
	"github.com/volatiletech/null/v8"
	"github.com/volatiletech/sqlboiler/v4/boil"
)

type CredStore interface {
	Store(ctx context.Context, user common.Address, cred *service.Credential) error
	Retrieve(_ context.Context, user common.Address) (*service.Credential, error)
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
	store          CredStore
	onboarding     *service.OnboardingService
	pdb            *db.Store
	devicesService service.DevicesGRPCService
}

func NewTeslaController(settings *config.Settings, logger *zerolog.Logger, teslaFleetAPISvc service.TeslaFleetAPIService, ddSvc service.DeviceDefinitionsAPIService, identitySvc service.IdentityAPIService, store CredStore, onboardingSvc *service.OnboardingService, pdb *db.Store) *TeslaController {
	var requiredScopes []string
	if settings.TeslaRequiredScopes != "" {
		requiredScopes = strings.Split(settings.TeslaRequiredScopes, ",")
	}
	devicesService, err := service.NewDevicesGRPCService(settings, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize DevicesGRPCService")
	}

	return &TeslaController{
		settings:       settings,
		logger:         logger,
		fleetAPISvc:    teslaFleetAPISvc,
		ddSvc:          ddSvc,
		identitySvc:    identitySvc,
		requiredScopes: requiredScopes,
		store:          store,
		onboarding:     onboardingSvc,
		pdb:            pdb,
		devicesService: devicesService,
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
// @Description Subscribes a vehicle for telemetry data using the provided vehicle token ID and authorization details in the request body.
// @Tags        tesla,subscribe
// @Accept      json
// @Produce     json
// @Param       vehicleTokenId path string true "OnboardingService Token ID"
// @Param       body CompleteOAuthExchangeRequest  "Authorization details"
// @Security    BearerAuth
// @Success     200 {object} map[string]string "Successfully subscribed to vehicle telemetry."
// @Failure     400 {object} fiber.Error "Bad Request"
// @Failure     401 {object} fiber.Error "Unauthorized"
// @Failure     404 {object} fiber.Error "OnboardingService not found or owner information is missing."
// @Failure     500 {object} fiber.Error "Internal server error"
// @Router      /v1/tesla/telemetry/subscribe/{vehicleTokenId} [post]
func (t *TeslaController) TelemetrySubscribe(c *fiber.Ctx) error {
	vehicleTokenId := c.Params("vehicleTokenId")
	if vehicleTokenId == "" {
		t.logger.Warn().Msg("VehicleTokenId is missing in the request path.")
		return fiber.NewError(fiber.StatusBadRequest, "VehicleTokenId is required in the request path.")
	}

	// Logger setup
	logger := helpers.GetLogger(c, t.logger).With().
		Str("Name", "Telemetry/Subscribe").
		Logger()

	logger.Debug().Msgf("Received telemetry subscribe request for %s.", vehicleTokenId)

	// Fetch wallet address
	walletAddress := helpers.GetWallet(c)
	if walletAddress != t.settings.MobileAppDevLicense {
		return fiber.NewError(fiber.StatusUnauthorized, fmt.Sprintf("Dev license %s is not allowed to subscribe to telemetry.", walletAddress.Hex()))
	}

	// finish getting the access token
	teslaAuth, err := t.getAccessToken(c)
	if err != nil {
		logger.Err(err).Msg("Failed to get access token.")
		return err
	}

	// Call identity to retrieve SyntheticDevice Address
	vehicle, err := t.fetchVehicle(vehicleTokenId)
	if err != nil {
		return err
	}

	// get VIN using the synthetic device address
	// TODO implement transactions handling here
	device, err := dbmodels.SyntheticDevices(
		dbmodels.SyntheticDeviceWhere.Address.EQ(common.HexToAddress(vehicle.SyntheticDevice.Address).Bytes()),
	).One(c.Context(), t.pdb.DBS().Reader)
	if err != nil {
		logger.Err(err).Msg("Failed to find synthetic device.")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to find synthetic device.")
	}

	// Call SubscribeForTelemetryData
	if err := t.fleetAPISvc.SubscribeForTelemetryData(c.Context(), teslaAuth.AccessToken, device.Vin); err != nil {
		logger.Err(err).Msg("Error registering for telemetry")
		var subErr *service.TeslaSubscriptionError
		if errors.As(err, &subErr) {
			switch subErr.Type {
			case service.KeyUnpaired:
				return fiber.NewError(fiber.StatusBadRequest, "Virtual key not paired with vehicle.")
			case service.UnsupportedVehicle:
				return fiber.NewError(fiber.StatusBadRequest, "Pre-2021 Model S and X do not support telemetry.")
			case service.UnsupportedFirmware:
				return fiber.NewError(fiber.StatusBadRequest, "OnboardingService firmware version is earlier than 2024.26.")
			}
		}
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to update telemetry configuration.")
	}

	// We know refresh token ttl is 3 months, so we set it to 3 months from now.
	refreshExpiry := time.Now().AddDate(0, 3, 0)

	creds := service.Credential{
		AccessToken:   teslaAuth.AccessToken,
		RefreshToken:  teslaAuth.RefreshToken,
		AccessExpiry:  teslaAuth.Expiry,
		RefreshExpiry: refreshExpiry,
	}

	err = t.UpdateCredsAndStatusToSuccess(c.Context(), device, &creds)
	if err != nil {
		logger.Err(err).Msg("Failed to update telemetry credentials.")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to update telemetry credentials.")
	}

	logger.Info().Msgf("Successfully subscribed to telemetry vehicle: %s.", vehicleTokenId)
	return c.JSON(fiber.Map{"message": "Successfully subscribed to vehicle telemetry."})
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
func (t *TeslaController) UnsubscribeTelemetry(c *fiber.Ctx) error {
	vehicleTokenId := c.Params("vehicleTokenId")
	if vehicleTokenId == "" {
		t.logger.Warn().Msg("VehicleTokenId is missing in the request path.")
		return fiber.NewError(fiber.StatusBadRequest, "VehicleTokenId is required in the request path.")
	}

	// Logger setup
	logger := helpers.GetLogger(c, t.logger).With().
		Str("Name", "Telemetry/Unsubscribe").
		Logger()

	logger.Info().Msgf("Received telemetry unsubscribe request for %s.", vehicleTokenId)

	// Fetch wallet address
	walletAddress := helpers.GetWallet(c)
	if walletAddress != t.settings.MobileAppDevLicense {
		return fiber.NewError(fiber.StatusUnauthorized, fmt.Sprintf("Dev license %s is not allowed to unsubscribe from telemetry.", walletAddress.Hex()))
	}

	// Get partners token
	partnersTokenResp, err := t.fleetAPISvc.GetPartnersToken(c.Context())
	if err != nil {
		logger.Err(err).Msg("Failed to get partners token.")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to get partners token.")
	}

	// Validate access token
	if partnersTokenResp.AccessToken == "" {
		return fiber.NewError(fiber.StatusInternalServerError, "Partners token response did not contain an access token.")
	}

	vehicle, err := t.fetchVehicle(vehicleTokenId)
	if err != nil {
		return err
	}

	// get VIN using the synthetic device address
	device, err := dbmodels.SyntheticDevices(
		dbmodels.SyntheticDeviceWhere.Address.EQ(common.HexToAddress(vehicle.SyntheticDevice.Address).Bytes())).One(c.Context(), t.pdb.DBS().Reader)
	if err != nil {
		logger.Err(err).Msg("Failed to find synthetic device.")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to find synthetic device.")
	}

	// Call the UnSubscribeFromTelemetryData function
	err = t.fleetAPISvc.UnSubscribeFromTelemetryData(c.Context(), partnersTokenResp.AccessToken, device.Vin)
	if err != nil {
		logger.Err(err).Str("vin", device.Vin).Msg("Failed to unsubscribe from telemetry data")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to unsubscribe from telemetry data")
	}

	stopErr := t.devicesService.StopTeslaTask(c.Context(), vehicle.TokenID)
	if stopErr != nil {
		logger.Err(stopErr).Msgf("Failed to stop Tesla task for synthetic device, tokenID: %s.", vehicleTokenId)
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to stop Tesla task for synthetic device.")
	}

	device.SubscriptionStatus = null.String{String: "inactive", Valid: true}
	// update synthetic device status
	_, err = device.Update(c.Context(), t.pdb.DBS().Writer, boil.Infer())
	if err != nil {
		logger.Err(err).Msg("Failed to update synthetic device status.")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to update synthetic device status.")
	}

	logger.Info().Msgf(`Successfully unsubscribed vehicle %s from telemetry data.`, vehicleTokenId)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Successfully unsubscribed from telemetry data",
	})
}

func (t *TeslaController) ListVehicles(c *fiber.Ctx) error {
	walletAddress := helpers.GetWallet(c)
	logger := helpers.GetLogger(c, t.logger)

	teslaAuth, err := t.getAccessToken(c)
	if err != nil {
		return err
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
		AccessToken:   teslaAuth.AccessToken,
		RefreshToken:  teslaAuth.RefreshToken,
		AccessExpiry:  teslaAuth.Expiry,
		RefreshExpiry: time.Now().AddDate(0, 3, 0),
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

		record, err := t.onboarding.GetVehicleByVin(c.Context(), v.VIN)
		if err != nil {
			if !errors.Is(err, service.ErrVehicleNotFound) {
				logger.Err(err).Str("vin", v.VIN).Msg("Failed to fetch record.")
			}
		}

		if record == nil {
			err = t.onboarding.InsertVinToDB(c.Context(), &dbmodels.Onboarding{
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

func (t *TeslaController) getAccessToken(c *fiber.Ctx) (*service.TeslaAuthCodeResponse, error) {
	var reqBody CompleteOAuthExchangeRequest
	if err := c.BodyParser(&reqBody); err != nil {
		t.logger.Err(err).Msg("Failed to parse request body OR it is empty.")
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

	teslaAuth, err := t.fleetAPISvc.CompleteTeslaAuthCodeExchange(c.Context(), reqBody.AuthorizationCode, reqBody.RedirectURI)
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
func (tc *TeslaController) fetchVehicle(vehicleTokenId string) (*models.Vehicle, error) {
	tokenID, convErr := helpers.StringToInt64(vehicleTokenId)
	if convErr != nil {
		tc.logger.Err(convErr).Msg("Failed to convert vehicleTokenId to int64.")
		return nil, fiber.NewError(fiber.StatusBadRequest, "Invalid vehicle token ID format.")
	}
	vehicle, vehErr := tc.identitySvc.FetchVehicleByTokenID(tokenID)
	if vehErr != nil {
		tc.logger.Err(vehErr).Msg("Failed to fetch vehicle by token ID.")
		return nil, fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch vehicle information.")
	}

	if vehicle == nil || vehicle.Owner == "" || vehicle.SyntheticDevice.Address == "" {
		tc.logger.Warn().Msg("OnboardingService not found or owner information or synthetic device address is missing.")
		return nil, fiber.NewError(fiber.StatusNotFound, "OnboardingService not found or owner information or synthetic device address is missing.")
	}
	return vehicle, nil
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

// UpdateCredsAndStatusToSuccess stores the given credential for the given synthDevice.
// This function encrypts the access and refresh tokens before saving them to the database.
// TODO implement encryption using KMS
func (t *TeslaController) UpdateCredsAndStatusToSuccess(c context.Context, synthDevice *dbmodels.SyntheticDevice, creds *service.Credential) error {
	encCreds, err := t.store.EncryptTokens(creds)
	if err != nil {
		return err
	}

	// store encrypted credentials
	synthDevice.AccessToken = null.String{String: encCreds.AccessToken, Valid: true}
	synthDevice.AccessExpiresAt = null.TimeFrom(encCreds.AccessExpiry)
	synthDevice.RefreshToken = null.String{String: encCreds.RefreshToken, Valid: true}
	synthDevice.RefreshExpiresAt = null.TimeFrom(encCreds.RefreshExpiry)

	// update status
	synthDevice.SubscriptionStatus = null.String{String: "active", Valid: true}

	// Save the changes to the database
	// todo add transaction handling
	_, err = synthDevice.Update(c, t.pdb.DBS().Writer, boil.Infer())
	if err != nil {
		return err
	}

	return nil
}
