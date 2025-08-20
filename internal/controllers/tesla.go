package controllers

import (
	"context"
	"fmt"
	"regexp"
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
}

func NewTeslaController(settings *config.Settings, logger *zerolog.Logger, teslaFleetAPISvc service.TeslaFleetAPIService, ddSvc service.DeviceDefinitionsAPIService, identitySvc service.IdentityAPIService, store CredStore, onboardingSvc *service.OnboardingService, pdb *db.Store) *TeslaController {
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
// @Description Subscribes a vehicle for telemetry data using the provided vehicle token ID and authorization details in the request body.
// @Tags        tesla,subscribe
// @Accept      json
// @Produce     json
// @Param       vehicleTokenId path string true "OnboardingService Token ID"
// @Param       payload body CompleteOAuthExchangeRequest true  "Authorization details"
// @Security    BearerAuth
// @Success     200 {object} map[string]string "Successfully subscribed to vehicle telemetry."
// @Failure     400 {object} fiber.Error "Bad Request"
// @Failure     401 {object} fiber.Error "Unauthorized"
// @Failure     404 {object} fiber.Error "OnboardingService not found or owner information is missing."
// @Failure     500 {object} fiber.Error "Internal server error"
// @Router      /v1/tesla/telemetry/subscribe/{vehicleTokenId} [post]
func (tc *TeslaController) TelemetrySubscribe(c *fiber.Ctx) error {
	vehicleTokenId := c.Params("vehicleTokenId")
	if vehicleTokenId == "" {
		tc.logger.Warn().Msg("VehicleTokenId is missing in the request path.")
		subscribeTelemetryFailureCount.Inc()
		return fiber.NewError(fiber.StatusBadRequest, "VehicleTokenId is required in the request path.")
	}

	logger := helpers.GetLogger(c, tc.logger).With().
		Str("Name", "Telemetry/Subscribe").
		Logger()

	logger.Debug().Msgf("Received telemetry subscribe request for %s.", vehicleTokenId)

	walletAddress := helpers.GetWallet(c)
	if walletAddress != tc.settings.MobileAppDevLicense {
		subscribeTelemetryFailureCount.Inc()
		return fiber.NewError(fiber.StatusUnauthorized, fmt.Sprintf("Dev license %s is not allowed to subscribe to telemetry.", walletAddress.Hex()))
	}

	teslaAuth, err := tc.getAccessToken(c)
	if err != nil {
		logger.Err(err).Msg("Failed to get access token.")
		subscribeTelemetryFailureCount.Inc()
		return err
	}

	vehicle, err := tc.fetchVehicle(vehicleTokenId)
	if err != nil {
		subscribeTelemetryFailureCount.Inc()
		return err
	}

	device, err := dbmodels.SyntheticDevices(
		dbmodels.SyntheticDeviceWhere.Address.EQ(common.HexToAddress(vehicle.SyntheticDevice.Address).Bytes()),
	).One(c.Context(), tc.pdb.DBS().Reader)
	if err != nil {
		logger.Err(err).Msg("Failed to find synthetic device.")
		subscribeTelemetryFailureCount.Inc()
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to find synthetic device.")
	}

	if err := tc.fleetAPISvc.SubscribeForTelemetryData(c.Context(), teslaAuth.AccessToken, device.Vin); err != nil {
		logger.Err(err).Msg("Error registering for telemetry")
		subscribeTelemetryFailureCount.Inc()
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to update telemetry configuration.")
	}

	// TODO when we sync devices-api and tesla-oracle dbs or migrated commands, we should fail the subscription if the task fails to start,
	startErr := tc.devicesService.StartTeslaTask(c.Context(), vehicle.TokenID)
	if startErr != nil {
		logger.Warn().Err(startErr).Msg("Failed to start Tesla task for synthetic device.")
	}

	refreshExpiry := time.Now().AddDate(0, 3, 0)
	creds := service.Credential{
		AccessToken:   teslaAuth.AccessToken,
		RefreshToken:  teslaAuth.RefreshToken,
		AccessExpiry:  teslaAuth.Expiry,
		RefreshExpiry: refreshExpiry,
	}

	err = tc.UpdateCredsAndStatusToSuccess(c.Context(), device, &creds)
	if err != nil {
		logger.Err(err).Msg("Failed to update telemetry credentials.")
		subscribeTelemetryFailureCount.Inc()
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to update telemetry credentials.")
	}

	logger.Info().Msgf("Successfully subscribed to telemetry vehicle: %s.", vehicleTokenId)
	subscribeTelemetrySuccessCount.Inc()
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
func (tc *TeslaController) UnsubscribeTelemetry(c *fiber.Ctx) error {
	vehicleTokenId := c.Params("vehicleTokenId")
	if vehicleTokenId == "" {
		tc.logger.Warn().Msg("VehicleTokenId is missing in the request path.")
		unsubscribeTelemetryFailureCount.Inc()
		return fiber.NewError(fiber.StatusBadRequest, "VehicleTokenId is required in the request path.")
	}

	logger := helpers.GetLogger(c, tc.logger).With().
		Str("Name", "Telemetry/Unsubscribe").
		Logger()

	logger.Info().Msgf("Received telemetry unsubscribe request for %s.", vehicleTokenId)

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

	vehicle, err := tc.fetchVehicle(vehicleTokenId)
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

	device.SubscriptionStatus = null.String{String: "inactive", Valid: true}
	_, err = device.Update(c.Context(), tc.pdb.DBS().Writer, boil.Infer())
	if err != nil {
		logger.Err(err).Msg("Failed to update synthetic device status.")
		unsubscribeTelemetryFailureCount.Inc()
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to update synthetic device status.")
	}

	logger.Info().Msgf(`Successfully unsubscribed vehicle %s from telemetry data.`, vehicleTokenId)
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

	fleetTelemetryCapable := IsFleetTelemetryCapable(fleetStatus)

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

// GetFleetStatus godoc
// @Summary     Get fleet status
// @Description Retrieves detailed fleet status information for a Tesla vehicle, including virtual key connection status and telemetry capabilities.
// @Tags        tesla,fleet
// @Accept      json
// @Produce     json
// @Param       vin query string true "Vehicle VIN"
// @Security    BearerAuth
// @Success     200 {object} service.VehicleFleetStatus "Fleet status details"
// @Failure     400 {object} fiber.Error "Bad Request"
// @Failure     401 {object} fiber.Error "Unauthorized"
// @Failure     500 {object} fiber.Error "Internal server error"
// @Router      /v1/tesla/fleet-status [get]
func (tc *TeslaController) GetFleetStatus(c *fiber.Ctx) error {
	walletAddress := helpers.GetWallet(c)

	var params VinInput
	if err := c.QueryParser(&params); err != nil {
		tc.logger.Err(err).Msgf("Failed to parse request URL params")
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

	return c.JSON(fleetStatus)
}

type VirtualKeyStatusResponse struct {
	Added  bool             `json:"added"`
	Status VirtualKeyStatus `json:"status" swaggertype:"string"`
}

type VirtualKeyStatus int

const (
	Incapable VirtualKeyStatus = iota
	Paired
	Unpaired
)

func (s VirtualKeyStatus) String() string {
	switch s {
	case Incapable:
		return "Incapable"
	case Paired:
		return "Paired"
	case Unpaired:
		return "Unpaired"
	}
	return ""
}

func (s VirtualKeyStatus) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s *VirtualKeyStatus) UnmarshalText(text []byte) error {
	switch str := string(text); str {
	case "Incapable":
		*s = Incapable
	case "Paired":
		*s = Paired
	case "Unpaired":
		*s = Unpaired
	default:
		return fmt.Errorf("unrecognized status %q", str)
	}
	return nil
}

func IsFleetTelemetryCapable(fs *service.VehicleFleetStatus) bool {
	// We used to check for the presence of a meaningful value (not ""
	// or "unknown") for fleet_telemetry_version, but this started
	// populating on old cars that are not capable of streaming.
	return fs.VehicleCommandProtocolRequired || !fs.DiscountedDeviceData
}

var teslaFirmwareStart = regexp.MustCompile(`^(\d{4})\.(\d+)`)

func IsFirmwareFleetTelemetryCapable(v string) (bool, error) {
	m := teslaFirmwareStart.FindStringSubmatch(v)
	if len(m) == 0 {
		return false, fmt.Errorf("unexpected firmware version format %q", v)
	}

	year, err := strconv.Atoi(m[1])
	if err != nil {
		return false, fmt.Errorf("couldn't parse year %q", m[1])
	}

	week, err := strconv.Atoi(m[2])
	if err != nil {
		return false, fmt.Errorf("couldn't parse week %q", m[2])
	}

	return year > 2024 || year == 2024 && week >= 26, nil
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

type VinInput struct {
	VIN string `json:"vin"`
}

type DeviceDefinition struct {
	Make               string `json:"make"`
	Model              string `json:"model"`
	Year               int    `json:"year"`
	DeviceDefinitionID string `json:"id"`
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

// UpdateCredsAndStatusToSuccess stores the given credential for the given synthDevice.
// This function encrypts the access and refresh tokens before saving them to the database.
// TODO implement encryption using KMS
func (tc *TeslaController) UpdateCredsAndStatusToSuccess(c context.Context, synthDevice *dbmodels.SyntheticDevice, creds *service.Credential) error {
	encCreds, err := tc.credStore.EncryptTokens(creds)
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
	_, err = synthDevice.Update(c, tc.pdb.DBS().Writer, boil.Infer())
	if err != nil {
		return err
	}

	return nil
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

var unsubscribeTelemetrySuccessCount = promauto.NewCounter(
	prometheus.CounterOpts{
		Namespace: "tesla_oracle",
		Subsystem: "tesla",
		Name:      "unsubscribe_telemetry_success_total",
		Help:      "Total number of successful telemetry unsubscriptions.",
	},
)

var unsubscribeTelemetryFailureCount = promauto.NewCounter(
	prometheus.CounterOpts{
		Namespace: "tesla_oracle",
		Subsystem: "tesla",
		Name:      "unsubscribe_telemetry_failure_total",
		Help:      "Total number of failed telemetry unsubscriptions.",
	},
)

var subscribeTelemetrySuccessCount = promauto.NewCounter(
	prometheus.CounterOpts{
		Namespace: "tesla_oracle",
		Subsystem: "tesla",
		Name:      "subscribe_telemetry_success_total",
		Help:      "Total number of successful telemetry subscriptions.",
	},
)

var subscribeTelemetryFailureCount = promauto.NewCounter(
	prometheus.CounterOpts{
		Namespace: "tesla_oracle",
		Subsystem: "tesla",
		Name:      "subscribe_telemetry_failure_total",
		Help:      "Total number of failed telemetry subscriptions.",
	},
)
