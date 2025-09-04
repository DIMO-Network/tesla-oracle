package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/shared/pkg/logfields"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/aarondl/null/v8"
	"github.com/ethereum/go-ethereum/common"
	"github.com/friendsofgo/errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
)

// Domain errors
var (
	ErrBadRequest               = errors.New("bad request")
	ErrUnauthorized             = errors.New("unauthorized access")
	ErrDevLicenseNotAllowed     = errors.New("dev license not allowed for this operation")
	ErrVehicleNotFound          = errors.New("vehicle not found")
	ErrSyntheticDeviceNotFound  = errors.New("synthetic device not found")
	ErrVehicleOwnershipMismatch = errors.New("vehicle does not belong to authenticated user")
	ErrNoCredentials            = errors.New("no credentials found for vehicle")
	ErrCredentialDecryption     = errors.New("failed to decrypt credentials")
	ErrTokenExpired             = errors.New("refresh token has expired")
	ErrTokenRefreshFailed       = errors.New("failed to refresh access token")
	ErrFleetStatusCheck         = errors.New("error checking fleet status")
	ErrTelemetryNotReady        = errors.New("vehicle not ready for telemetry subscription")
	ErrTelemetryLimitReached    = errors.New("telemetry subscription limit reached")
	ErrTelemetryConfigFailed    = errors.New("failed to update telemetry configuration")
	ErrSubscriptionStatusUpdate = errors.New("failed to update subscription status")
	ErrPartnersToken            = errors.New("failed to get partners token")
	ErrTelemetryUnsubscribe     = errors.New("failed to unsubscribe from telemetry data")
	ErrDeviceDefinitionNotFound = errors.New("device definition not found")
	ErrCredentialStore          = errors.New("failed to store credentials")
	ErrOAuthVehiclesFetch       = errors.New("failed to fetch vehicles from Tesla")
	ErrOnboardingRecordCreation = errors.New("failed to create onboarding record")
	ErrVINDecoding              = errors.New("failed to decode VIN")
)

type TeslaService struct {
	settings     *config.Settings
	logger       *zerolog.Logger
	Cipher       cipher.Cipher
	repositories *repository.Repositories
	fleetAPISvc  TeslaFleetAPIService
	identitySvc  IdentityAPIService
	ddSvc        DeviceDefinitionsAPIService
	devicesSvc   DevicesGRPCService
}

func NewTeslaService(settings *config.Settings, logger *zerolog.Logger, cipher cipher.Cipher, repositories *repository.Repositories, fleetAPISvc TeslaFleetAPIService, identitySvc IdentityAPIService, ddSvc DeviceDefinitionsAPIService, devicesService DevicesGRPCService) *TeslaService {
	return &TeslaService{
		settings:     settings,
		logger:       logger,
		Cipher:       cipher,
		repositories: repositories,
		fleetAPISvc:  fleetAPISvc,
		identitySvc:  identitySvc,
		ddSvc:        ddSvc,
		devicesSvc:   devicesService,
	}
}

// GetOrRefreshAccessToken checks if the access token for the given synthetic device has expired.
// If the access token is expired and the refresh token is still valid, it attempts to refresh the access token.
// If the refresh token is expired, it returns an unauthorized error.
func (ts *TeslaService) GetOrRefreshAccessToken(ctx context.Context, sd *dbmodels.SyntheticDevice) (string, error) {
	accessToken, err := ts.Cipher.Decrypt(sd.AccessToken.String)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrCredentialDecryption, err.Error())
	}

	if !sd.AccessExpiresAt.IsZero() && time.Now().After(sd.AccessExpiresAt.Time) {
		refreshToken, err := ts.Cipher.Decrypt(sd.RefreshToken.String)
		if err != nil {
			return "", fmt.Errorf("%w: %s", ErrCredentialDecryption, err.Error())
		}
		if !sd.RefreshExpiresAt.IsZero() && time.Now().Before(sd.RefreshExpiresAt.Time) {
			tokens, errRefresh := ts.fleetAPISvc.RefreshToken(ctx, refreshToken)
			if errRefresh != nil {
				return "", fmt.Errorf("%w: %s", ErrTokenRefreshFailed, errRefresh.Error())
			}
			expiryTime := time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
			creds := repository.Credential{
				AccessToken:   tokens.AccessToken,
				RefreshToken:  tokens.RefreshToken,
				AccessExpiry:  expiryTime,
				RefreshExpiry: time.Now().AddDate(0, 3, 0),
			}
			errUpdate := ts.repositories.Vehicle.UpdateSyntheticDeviceCredentials(ctx, sd, &creds)
			if errUpdate != nil {
				ts.logger.Warn().Err(errUpdate).Msg("Failed to update credentials after refresh.")
			}
			return tokens.AccessToken, nil
		} else {
			return "", ErrTokenExpired
		}
	}

	return accessToken, nil
}

// StopTeslaTask stops Tesla task for the given vehicle token ID.
func (ts *TeslaService) StopTeslaTask(ctx context.Context, tokenID int64) error {
	if ts.devicesSvc == nil {
		ts.logger.Warn().Msg("Devices GRPC service is disabled")
		return nil
	}
	return ts.devicesSvc.StopTeslaTask(ctx, tokenID)
}

// SubscribeToTelemetry handles the complete telemetry subscription workflow
func (ts *TeslaService) SubscribeToTelemetry(ctx context.Context, tokenID int64, walletAddress common.Address) error {
	// Validate dev license
	if walletAddress != ts.settings.MobileAppDevLicense {
		return ErrDevLicenseNotAllowed
	}

	// Get synthetic device
	sd, err := ts.repositories.Vehicle.GetSyntheticDeviceByTokenID(ctx, tokenID)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrSyntheticDeviceNotFound, err.Error())
	}

	// Start streaming or polling
	err = ts.startStreamingOrPolling(ctx, sd, tokenID)
	if err != nil {
		return err
	}

	// Update subscription status
	err = ts.repositories.Vehicle.UpdateSyntheticDeviceSubscriptionStatus(ctx, sd, "active")
	if err != nil {
		ts.logger.Err(err).Msg("Failed to update subscription status.")
		return fmt.Errorf("%w: %s", ErrSubscriptionStatusUpdate, err.Error())
	}

	return nil
}

// StartVehicleDataFlow handles the complete data flow startup workflow
func (ts *TeslaService) StartVehicleDataFlow(ctx context.Context, tokenID int64, walletAddress common.Address) error {
	// Validate vehicle ownership
	err := ts.validateVehicleOwnership(tokenID, walletAddress)
	if err != nil {
		return err
	}

	// Get synthetic device
	sd, err := ts.repositories.Vehicle.GetSyntheticDeviceByTokenID(ctx, tokenID)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrSyntheticDeviceNotFound, err.Error())
	}

	// Start streaming or polling
	return ts.startStreamingOrPolling(ctx, sd, tokenID)
}

// UnsubscribeFromTelemetry handles the complete telemetry unsubscription workflow
func (ts *TeslaService) UnsubscribeFromTelemetry(ctx context.Context, tokenID int64, walletAddress common.Address) error {
	// Validate dev license
	if walletAddress != ts.settings.MobileAppDevLicense {
		return ErrDevLicenseNotAllowed
	}

	// Get partners token
	partnersTokenResp, err := ts.fleetAPISvc.GetPartnersToken(ctx)
	if err != nil {
		ts.logger.Err(err).Msg("Failed to get partners token.")
		return fmt.Errorf("%w: %s", ErrPartnersToken, err.Error())
	}

	if partnersTokenResp.AccessToken == "" {
		return ErrPartnersToken
	}

	// Fetch vehicle
	vehicle, err := ts.fetchVehicle(tokenID)
	if err != nil {
		return err
	}

	// Get synthetic device
	device, err := ts.repositories.Vehicle.GetSyntheticDeviceByAddress(ctx, common.HexToAddress(vehicle.SyntheticDevice.Address))
	if err != nil {
		ts.logger.Err(err).Msg("Failed to find synthetic device.")
		return fmt.Errorf("%w: %s", ErrSyntheticDeviceNotFound, err.Error())
	}

	// Unsubscribe from telemetry data
	err = ts.fleetAPISvc.UnSubscribeFromTelemetryData(ctx, partnersTokenResp.AccessToken, device.Vin)
	if err != nil {
		ts.logger.Err(err).Str("vin", device.Vin).Msg("Failed to unsubscribe from telemetry data")
		return fmt.Errorf("%w: %s", ErrTelemetryUnsubscribe, err.Error())
	}

	// Stop Tesla task
	stopErr := ts.StopTeslaTask(ctx, vehicle.TokenID)
	if stopErr != nil {
		ts.logger.Warn().Err(stopErr).Msg("Failed to stop Tesla task for synthetic device.")
	}

	// Update subscription status
	err = ts.repositories.Vehicle.UpdateSyntheticDeviceSubscriptionStatus(ctx, device, "inactive")
	if err != nil {
		ts.logger.Err(err).Msg("Failed to update subscription status.")
		return fmt.Errorf("%w: %s", ErrSubscriptionStatusUpdate, err.Error())
	}

	return nil
}

// ProcessAuthCodeExchange handles complete auth code exchange and validation flow
func (ts *TeslaService) ProcessAuthCodeExchange(ctx context.Context, authCode, redirectURI string, requiredScopes []string) (*TeslaAuthCodeResponse, error) {
	// Exchange auth code for tokens
	teslaAuth, err := ts.fleetAPISvc.CompleteTeslaAuthCodeExchange(ctx, authCode, redirectURI)
	if err != nil {
		return nil, err
	}

	// Validate refresh token is present
	if teslaAuth.RefreshToken == "" {
		return nil, fmt.Errorf("code exchange did not return a refresh token")
	}

	// Validate token has required scopes
	if err := ts.validateAccessTokenWithScopes(teslaAuth.AccessToken, requiredScopes); err != nil {
		return nil, err
	}

	return teslaAuth, nil
}

// CompleteOAuthFlow handles the complete OAuth flow including vehicle list processing
func (ts *TeslaService) CompleteOAuthFlow(ctx context.Context, walletAddress common.Address, teslaAuth *TeslaAuthCodeResponse) ([]models.TeslaVehicleRes, error) {
	// Store credentials
	if err := ts.repositories.Credential.Store(ctx, walletAddress, &repository.Credential{
		AccessToken:   teslaAuth.AccessToken,
		RefreshToken:  teslaAuth.RefreshToken,
		AccessExpiry:  teslaAuth.Expiry,
		RefreshExpiry: time.Now().AddDate(0, 3, 0),
	}); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCredentialStore, err.Error())
	}

	// Get vehicle list from Tesla
	vehicles, err := ts.fleetAPISvc.GetVehicles(ctx, teslaAuth.AccessToken)
	if err != nil {
		if errors.Is(err, ErrWrongRegion) {
			return nil, fmt.Errorf("%w: region detection failed", ErrOAuthVehiclesFetch)
		}
		return nil, fmt.Errorf("%w: %s", ErrOAuthVehiclesFetch, err.Error())
	}

	// Process each vehicle
	response := make([]models.TeslaVehicleRes, 0, len(vehicles))
	for _, v := range vehicles {
		// Decode VIN
		ddRes, err := ts.decodeTeslaVIN(v.VIN)
		if err != nil {
			ts.logger.Err(err).Str("vin", v.VIN).Msg("Failed to decode Tesla VIN.")
			return nil, err
		}

		// Check/create onboarding record
		record, err := ts.repositories.Onboarding.GetOnboardingByVin(ctx, v.VIN)
		if err != nil {
			if !errors.Is(err, repository.ErrOnboardingVehicleNotFound) {
				ts.logger.Err(err).Str("vin", v.VIN).Msg("Failed to fetch record.")
			}
		}

		if record == nil {
			err = ts.repositories.Onboarding.InsertOnboarding(ctx, &dbmodels.Onboarding{
				Vin:                v.VIN,
				DeviceDefinitionID: null.String{String: ddRes.DeviceDefinitionID, Valid: true},
				OnboardingStatus:   23, // OnboardingStatusVendorValidationSuccess
				ExternalID:         null.String{String: strconv.Itoa(v.ID), Valid: true},
			})
			if err != nil {
				return nil, fmt.Errorf("%w: %s", ErrOnboardingRecordCreation, err.Error())
			}
		}

		// Build response
		response = append(response, models.TeslaVehicleRes{
			ExternalID: strconv.Itoa(v.ID),
			VIN:        v.VIN,
			Definition: models.DeviceDefinitionRes{
				Make:               ddRes.Manufacturer.Name,
				Model:              ddRes.Model,
				Year:               ddRes.Year,
				DeviceDefinitionID: ddRes.DeviceDefinitionID,
			},
		})
	}

	return response, nil
}

// GetVehicleStatus handles the complete vehicle status check workflow
func (ts *TeslaService) GetVehicleStatus(ctx context.Context, tokenID int64, walletAddress common.Address) (*models.StatusDecision, error) {
	// Validate vehicle ownership
	err := ts.validateVehicleOwnership(tokenID, walletAddress)
	if err != nil {
		return nil, err
	}

	// Get synthetic device
	sd, err := ts.repositories.Vehicle.GetSyntheticDeviceByTokenID(ctx, tokenID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrSyntheticDeviceNotFound, err.Error())
	}

	// Check if we have access token
	if sd == nil || sd.AccessToken.String == "" || sd.RefreshToken.String == "" {
		return nil, ErrNoCredentials
	}

	// Get or refresh access token
	accessToken, err := ts.GetOrRefreshAccessToken(ctx, sd)
	if err != nil {
		return nil, err
	}

	// get telemetry subscription status. we do not take into account polling here
	telemetryStatus, err := ts.fleetAPISvc.GetTelemetrySubscriptionStatus(ctx, accessToken, sd.Vin)
	if err != nil {
		// Log error but don't fail the request - telemetry status is optional
		ts.logger.Warn().Err(err).Str("vin", sd.Vin).Msg("Failed to get telemetry subscription status")
	}

	// Get status and decide on action
	return ts.decideOnAction(ctx, sd, telemetryStatus, accessToken, tokenID)
}

// GetVirtualKeyStatus handles virtual key status check workflow
func (ts *TeslaService) GetVirtualKeyStatus(ctx context.Context, vin string, walletAddress common.Address) (*models.VirtualKeyStatusResponse, error) {
	// Get credentials from repository
	teslaAuth, err := ts.repositories.Credential.Retrieve(ctx, walletAddress)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnauthorized, err.Error())
	}

	// Check fleet status
	fleetStatus, err := ts.fleetAPISvc.VirtualKeyConnectionStatus(ctx, teslaAuth.AccessToken, vin)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFleetStatusCheck, err.Error())
	}

	fleetTelemetryCapable := IsFleetTelemetryCapable(fleetStatus)

	var response = models.VirtualKeyStatusResponse{}
	response.Added = fleetStatus.KeyPaired
	if !fleetTelemetryCapable {
		response.Status = models.Incapable
	} else if fleetStatus.KeyPaired {
		response.Status = models.Paired
	} else {
		response.Status = models.Unpaired
	}

	return &response, nil
}

// fetchVehicle retrieves a vehicle from identity-api by its token ID.
func (ts *TeslaService) fetchVehicle(vehicleTokenId int64) (*models.Vehicle, error) {
	vehicle, err := ts.identitySvc.FetchVehicleByTokenID(vehicleTokenId)
	if err != nil {
		ts.logger.Err(err).Msg("Failed to fetch vehicle by token ID.")
		return nil, fmt.Errorf("%w: %s", ErrVehicleNotFound, err.Error())
	}

	if vehicle == nil || vehicle.Owner == "" || vehicle.SyntheticDevice.Address == "" {
		ts.logger.Warn().Msg("Vehicle not found or owner information or synthetic device address is missing.")
		return nil, ErrVehicleNotFound
	}
	return vehicle, nil
}

// validateAccessTokenWithScopes validates Tesla access token and required scopes
func (ts *TeslaService) validateAccessTokenWithScopes(accessToken string, requiredScopes []string) error {
	var claims struct {
		jwt.RegisteredClaims
		Scopes []string `json:"scp"`
		OUCode string   `json:"ou_code"`
	}

	_, _, err := jwt.NewParser().ParseUnverified(accessToken, &claims)
	if err != nil {
		return fmt.Errorf("access token is unparseable: %w", err)
	}

	var missingScopes []string
	for _, scope := range requiredScopes {
		found := false
		for _, claimScope := range claims.Scopes {
			if claimScope == scope {
				found = true
				break
			}
		}
		if !found {
			missingScopes = append(missingScopes, scope)
		}
	}

	if len(missingScopes) > 0 {
		return fmt.Errorf("missing required scopes: %s", strings.Join(missingScopes, ", "))
	}

	return nil
}

// validateVehicleOwnership checks if the vehicle belongs to the authenticated user.
func (ts *TeslaService) validateVehicleOwnership(tokenID int64, walletAddress common.Address) error {
	vehicle, err := ts.fetchVehicle(tokenID)
	if err != nil {
		return err
	}

	if vehicle == nil || vehicle.Owner != walletAddress.Hex() {
		return ErrVehicleOwnershipMismatch
	}

	return nil
}

// decodeTeslaVIN decodes a Tesla VIN to get device definition information.
func (ts *TeslaService) decodeTeslaVIN(vin string) (*models.DeviceDefinition, error) {
	decodeVIN, err := ts.ddSvc.DecodeVin(vin, "USA")
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrVINDecoding, err.Error())
	}

	dd, err := ts.getOrWaitForDeviceDefinition(decodeVIN.DeviceDefinitionID)
	if err != nil {
		return nil, err
	}

	return dd, nil
}

// getOrWaitForDeviceDefinition waits for a device definition to become available.
func (ts *TeslaService) getOrWaitForDeviceDefinition(deviceDefinitionID string) (*models.DeviceDefinition, error) {
	ts.logger.Debug().Str(logfields.DefinitionID, deviceDefinitionID).Msg("Waiting for device definition")
	for i := 0; i < 12; i++ {
		definition, err := ts.identitySvc.FetchDeviceDefinitionByID(deviceDefinitionID)
		if err != nil || definition == nil || definition.DeviceDefinitionID == "" {
			time.Sleep(5 * time.Second)
			ts.logger.Debug().Str(logfields.DefinitionID, deviceDefinitionID).Msgf("Still waiting, retry %d", i+1)
			continue
		}
		return definition, nil
	}

	return nil, ErrDeviceDefinitionNotFound
}

// startStreamingOrPolling determines whether to start streaming telemetry data or polling for a Tesla vehicle.
// It checks if the vehicle has valid credentials, refreshes the access token if necessary, and decides the next action.
func (ts *TeslaService) startStreamingOrPolling(ctx context.Context, sd *dbmodels.SyntheticDevice, tokenID int64) error {
	// check if we have access token
	if sd == nil || sd.AccessToken.String == "" || sd.RefreshToken.String == "" {
		return ErrNoCredentials
	}

	accessToken, err := ts.GetOrRefreshAccessToken(ctx, sd)
	if err != nil {
		return err
	}

	resp, err := ts.decideOnAction(ctx, sd, nil, accessToken, tokenID)
	if err != nil {
		return err
	}

	// call appropriate action
	switch resp.Action {
	case ActionSetTelemetryConfig:
		subStatus, err := ts.fleetAPISvc.GetTelemetrySubscriptionStatus(ctx, accessToken, sd.Vin)
		if err != nil {
			ts.logger.Err(err).Msg("Error checking telemetry subscription status")
			return fmt.Errorf("%w: %s", ErrTelemetryConfigFailed, err.Error())
		}
		if subStatus.LimitReached {
			return ErrTelemetryLimitReached
		}

		if err := ts.fleetAPISvc.SubscribeForTelemetryData(ctx, accessToken, sd.Vin); err != nil {
			ts.logger.Err(err).Msg("Error registering for telemetry")
			return fmt.Errorf("%w: %s", ErrTelemetryConfigFailed, err.Error())
		}

	case ActionStartPolling:
		startErr := ts.devicesSvc.StartTeslaTask(ctx, tokenID)
		if startErr != nil {
			ts.logger.Warn().Err(startErr).Msg("Failed to start Tesla task for synthetic device.")
		}

	default:
		return ErrTelemetryNotReady
	}

	return nil
}

// decideOnAction determines the next action for a Tesla vehicle based on its fleet status
// and telemetry configuration status. It evaluates the appropriate action using a decision tree.
func (ts *TeslaService) decideOnAction(ctx context.Context, sd *dbmodels.SyntheticDevice, telemetryStatus *VehicleTelemetryStatus, accessToken string, tokenID int64) (*models.StatusDecision, error) {
	// get vehicle status
	connectionStatus, err := ts.fleetAPISvc.VirtualKeyConnectionStatus(ctx, accessToken, sd.Vin)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFleetStatusCheck, err.Error())
	}

	// determine action based on status
	resp, err := DecisionTreeAction(connectionStatus, telemetryStatus, tokenID)
	if err != nil {
		ts.logger.Err(err)
		return nil, fmt.Errorf("error determining fleet action: %w", err)
	}
	return resp, nil
}
