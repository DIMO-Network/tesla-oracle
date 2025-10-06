package service

import (
	"context"
	er "errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/DIMO-Network/shared/pkg/logfields"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/aarondl/null/v8"
	"github.com/ethereum/go-ethereum/common"
	"github.com/friendsofgo/errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
)

type TeslaService struct {
	settings     *config.Settings
	logger       *zerolog.Logger
	repositories *repository.Repositories
	fleetAPISvc  core.TeslaFleetAPIService
	identitySvc  IdentityAPIService
	ddSvc        DeviceDefinitionsAPIService
	devicesSvc   DevicesGRPCService
	authManager  core.TeslaTokenManager
}

func NewTeslaService(settings *config.Settings, logger *zerolog.Logger, repositories *repository.Repositories, fleetAPISvc core.TeslaFleetAPIService, identitySvc IdentityAPIService, ddSvc DeviceDefinitionsAPIService, devicesService DevicesGRPCService, authManager core.TeslaTokenManager) *TeslaService {
	return &TeslaService{
		settings:     settings,
		logger:       logger,
		repositories: repositories,
		fleetAPISvc:  fleetAPISvc,
		identitySvc:  identitySvc,
		ddSvc:        ddSvc,
		devicesSvc:   devicesService,
		authManager:  authManager,
	}
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
		return core.ErrDevLicenseNotAllowed
	}

	// Get synthetic device
	sd, err := ts.repositories.Vehicle.GetSyntheticDeviceByTokenID(ctx, tokenID)
	if err != nil {
		return fmt.Errorf("%w: %s", core.ErrSyntheticDeviceNotFound, err.Error())
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
		return fmt.Errorf("%w: %s", core.ErrSubscriptionStatusUpdate, err.Error())
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
		return fmt.Errorf("%w: %s", core.ErrSyntheticDeviceNotFound, err.Error())
	}

	// Start streaming or polling
	return ts.startStreamingOrPolling(ctx, sd, tokenID)
}

// UnsubscribeFromTelemetry handles the complete telemetry unsubscription workflow
func (ts *TeslaService) UnsubscribeFromTelemetry(ctx context.Context, tokenID int64, walletAddress common.Address) error {
	// Validate dev license
	if walletAddress != ts.settings.MobileAppDevLicense {
		return core.ErrDevLicenseNotAllowed
	}

	// Get partners token
	partnersTokenResp, err := ts.fleetAPISvc.GetPartnersToken(ctx)
	if err != nil {
		ts.logger.Err(err).Msg("Failed to get partners token.")
		return fmt.Errorf("%w: %s", core.ErrPartnersToken, err.Error())
	}

	if partnersTokenResp.AccessToken == "" {
		return core.ErrPartnersToken
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
		return fmt.Errorf("%w: %s", core.ErrSyntheticDeviceNotFound, err.Error())
	}

	// Unsubscribe from telemetry data
	err = ts.fleetAPISvc.UnSubscribeFromTelemetryData(ctx, partnersTokenResp.AccessToken, device.Vin)
	if err != nil {
		ts.logger.Err(err).Str("vin", device.Vin).Msg("Failed to unsubscribe from telemetry data")
		return fmt.Errorf("%w: %s", core.ErrTelemetryUnsubscribe, err.Error())
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
		return fmt.Errorf("%w: %s", core.ErrSubscriptionStatusUpdate, err.Error())
	}

	return nil
}

// ProcessAuthCodeExchange handles complete auth code exchange and validation flow
func (ts *TeslaService) ProcessAuthCodeExchange(ctx context.Context, authCode, redirectURI string, requiredScopes []string) (*core.TeslaAuthCodeResponse, error) {
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

// processVehicleOnboarding handles onboarding record creation for a vehicle
func (ts *TeslaService) processVehicleOnboarding(ctx context.Context, vin string, externalID int, deviceDefinitionID string) error {
	// Check/create onboarding record
	record, err := ts.repositories.Onboarding.GetOnboardingByVin(ctx, vin)
	if err != nil {
		if !errors.Is(err, repository.ErrOnboardingVehicleNotFound) {
			ts.logger.Err(err).Str("vin", vin).Msg("Failed to fetch onboarding record.")
		}
	}

	if record == nil {
		err = ts.repositories.Onboarding.InsertOnboarding(ctx, &dbmodels.Onboarding{
			Vin:                vin,
			DeviceDefinitionID: null.String{String: deviceDefinitionID, Valid: true},
			OnboardingStatus:   23, // OnboardingStatusVendorValidationSuccess
			ExternalID:         null.String{String: strconv.Itoa(externalID), Valid: true},
		})
		if err != nil {
			return fmt.Errorf("%w: %s", core.ErrOnboardingRecordCreation, err.Error())
		}
	}

	return nil
}

// CompleteOAuthFlow handles the complete OAuth flow including vehicle list processing
func (ts *TeslaService) CompleteOAuthFlow(ctx context.Context, walletAddress common.Address, teslaAuth *core.TeslaAuthCodeResponse, withOnboarding bool, updateDBCredentials bool) ([]models.TeslaVehicleRes, error) {
	// Store credentials in cache
	creds := &repository.Credential{
		AccessToken:   teslaAuth.AccessToken,
		RefreshToken:  teslaAuth.RefreshToken,
		AccessExpiry:  teslaAuth.Expiry,
		RefreshExpiry: time.Now().AddDate(0, 3, 0),
	}
	if err := ts.repositories.Credential.Store(ctx, walletAddress, creds); err != nil {
		return nil, fmt.Errorf("%w: %s", core.ErrCredentialStore, err.Error())
	}

	// Get vehicle list from Tesla
	vehicles, err := ts.fleetAPISvc.GetVehicles(ctx, teslaAuth.AccessToken)
	if err != nil {
		if errors.Is(err, core.ErrWrongRegion) {
			return nil, fmt.Errorf("%w: region detection failed", core.ErrOAuthVehiclesFetch)
		}
		return nil, fmt.Errorf("%w: %s", core.ErrOAuthVehiclesFetch, err.Error())
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

		// Handle onboarding if requested
		if withOnboarding {
			if err := ts.processVehicleOnboarding(ctx, v.VIN, v.ID, ddRes.DeviceDefinitionID); err != nil {
				return nil, err
			}
		}

		// Update DB credentials if requested (for reauthentication)
		if updateDBCredentials {
			sd, err := ts.repositories.Vehicle.GetSyntheticDeviceByVin(ctx, v.VIN)
			if err != nil {
				ts.logger.Warn().Err(err).Str("vin", v.VIN).Msg("Failed to get synthetic device for credential update, skipping.")
			} else if sd != nil {
				err = ts.repositories.Vehicle.UpdateSyntheticDeviceCredentials(ctx, sd, creds)
				if err != nil {
					ts.logger.Warn().Err(err).Str("vin", v.VIN).Msg("Failed to update synthetic device credentials.")
				}
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
func (ts *TeslaService) GetVehicleStatus(ctx context.Context, tokenID int64, walletAddress common.Address, validateVehicleOwnership bool) (*models.StatusDecision, error) {
	// Validate vehicle ownership (disabled for admin)
	if validateVehicleOwnership {
		err := ts.validateVehicleOwnership(tokenID, walletAddress)
		if err != nil {
			return nil, err
		}
	}

	// Get synthetic device
	sd, err := ts.repositories.Vehicle.GetSyntheticDeviceByTokenID(ctx, tokenID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", core.ErrSyntheticDeviceNotFound, err.Error())
	}

	// Check if we have access token
	if sd == nil || sd.AccessToken.String == "" || sd.RefreshToken.String == "" {
		return nil, core.ErrNoCredentials
	}

	// Get or refresh access token
	accessToken, err := ts.authManager.GetOrRefreshAccessToken(ctx, sd)
	if err != nil {
		// Check if this is a token refresh error (either token expired or refresh failed)
		if er.Is(err, core.ErrTokenExpired) || (!er.Is(err, core.ErrCredentialDecryption) && !er.Is(err, core.ErrNoCredentials)) {
			decision, decisionErr := TokenRefreshDecisionTree(err)
			if decisionErr == nil {
				return decision, nil
			}
		}
		return nil, err
	}

	// Get status and decide on action
	resp, err := ts.decideOnAction(ctx, sd, accessToken, tokenID)
	if err != nil {
		return nil, err
	}

	switch resp.Action {
	case ActionSetTelemetryConfig:
		telemetryStatus, err := ts.fleetAPISvc.GetTelemetrySubscriptionStatus(ctx, accessToken, sd.Vin)
		if err != nil {
			// Log error but don't fail the request - telemetry status is optional
			ts.logger.Warn().Err(err).Str("vin", sd.Vin).Msg("Failed to get telemetry subscription status")
		} else {
			// Log telemetryStatus for debugging
			ts.logger.Debug().
				Interface("telemetryStatus", telemetryStatus).
				Str("vin", sd.Vin).
				Msg("Fetched telemetry subscription status")

			if telemetryStatus != nil && telemetryStatus.Configured {
				// Telemetry is already configured, return telemetry_configured status
				return &models.StatusDecision{
					Action:  ActionTelemetryConfigured,
					Message: MessageTelemetryConfigured,
				}, nil
			}
		}
	case ActionStartPolling:
		// For polling, we consider telemetry already started be devices-api
		return &models.StatusDecision{
			Action:  ActionTelemetryConfigured,
			Message: MessageTelemetryConfigured,
		}, nil
	}

	return resp, nil
}

// GetVirtualKeyStatus handles virtual key status check workflow
func (ts *TeslaService) GetVirtualKeyStatus(ctx context.Context, vin string, walletAddress common.Address) (*models.VirtualKeyStatusResponse, error) {
	// Get credentials from repository
	teslaAuth, err := ts.repositories.Credential.Retrieve(ctx, walletAddress)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", core.ErrUnauthorized, err.Error())
	}

	// Check fleet status
	fleetStatus, err := ts.fleetAPISvc.VirtualKeyConnectionStatus(ctx, teslaAuth.AccessToken, vin)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", core.ErrFleetStatusCheck, err.Error())
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

// ValidateCommandRequest validates command request and returns synthetic device
func (ts *TeslaService) ValidateCommandRequest(ctx context.Context, tokenID int64, command string) (*dbmodels.SyntheticDevice, error) {
	err := core.ValidateCommand(command)
	if err != nil {
		return nil, err
	}

	// Get synthetic device
	sd, err := ts.repositories.Vehicle.GetSyntheticDeviceByTokenID(ctx, tokenID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", core.ErrSyntheticDeviceNotFound, err.Error())
	}

	// Check subscription status - commands only allowed for active subscriptions
	if sd.SubscriptionStatus.String == "inactive" {
		ts.logger.Warn().
			Str("subscriptionStatus", sd.SubscriptionStatus.String).
			Int("vehicleTokenId", sd.VehicleTokenID.Int).
			Msgf("Dropping command request for vehicle due to subscription status")
		return nil, core.ErrInactiveSubscription
	}

	// TODO: Should we check if commands are enabled? Who enables them?
	ts.logger.Debug().Str("vin", sd.Vin).Msg("Command request validation passed")

	return sd, nil
}

// WakeUpVehicle wakes up a Tesla vehicle from sleep
func (ts *TeslaService) WakeUpVehicle(ctx context.Context, tokenID int64) (*core.TeslaVehicle, error) {

	// Get synthetic device
	sd, err := ts.repositories.Vehicle.GetSyntheticDeviceByTokenID(ctx, tokenID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", core.ErrSyntheticDeviceNotFound, err.Error())
	}

	// Get and refresh access token
	accessToken, err := ts.authManager.GetOrRefreshAccessToken(ctx, sd)
	if err != nil {
		ts.logger.Err(err).Msg("Failed to get access token for wake up")
		return nil, fmt.Errorf("%w: %s", core.ErrNoCredentials, err.Error())
	}

	// Wake up the vehicle via Tesla Fleet API
	vehicle, err := ts.fleetAPISvc.WakeUpVehicle(ctx, accessToken, sd.Vin)
	if err != nil {
		ts.logger.Err(err).Str("vin", sd.Vin).Msg("Failed to wake up vehicle")
		return nil, fmt.Errorf("failed to wake up vehicle: %w", err)
	}

	ts.logger.Info().Str("vin", sd.Vin).Str("state", vehicle.State).Msg("Vehicle wake up completed")
	return vehicle, nil
}

// fetchVehicle retrieves a vehicle from identity-api by its token ID.
func (ts *TeslaService) fetchVehicle(vehicleTokenId int64) (*models.Vehicle, error) {
	vehicle, err := ts.identitySvc.FetchVehicleByTokenID(vehicleTokenId)
	if err != nil {
		ts.logger.Err(err).Msg("Failed to fetch vehicle by token ID.")
		return nil, fmt.Errorf("%w: %s", core.ErrVehicleNotFound, err.Error())
	}

	if vehicle == nil || vehicle.Owner == "" || vehicle.SyntheticDevice.Address == "" {
		ts.logger.Warn().Msg("Vehicle not found or owner information or synthetic device address is missing.")
		return nil, core.ErrVehicleNotFound
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
		return core.ErrVehicleOwnershipMismatch
	}

	return nil
}

// decodeTeslaVIN decodes a Tesla VIN to get device definition information.
func (ts *TeslaService) decodeTeslaVIN(vin string) (*models.DeviceDefinition, error) {
	decodeVIN, err := ts.ddSvc.DecodeVin(vin, "USA")
	if err != nil {
		return nil, fmt.Errorf("%w: %s", core.ErrVINDecoding, err.Error())
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

	return nil, core.ErrDeviceDefinitionNotFound
}

// startStreamingOrPolling determines whether to start streaming telemetry data or polling for a Tesla vehicle.
// It checks if the vehicle has valid credentials, refreshes the access token if necessary, and decides the next action.
func (ts *TeslaService) startStreamingOrPolling(ctx context.Context, sd *dbmodels.SyntheticDevice, tokenID int64) error {
	// check if we have access token
	if sd == nil || sd.AccessToken.String == "" || sd.RefreshToken.String == "" {
		return core.ErrNoCredentials
	}

	accessToken, err := ts.authManager.GetOrRefreshAccessToken(ctx, sd)
	if err != nil {
		return err
	}

	resp, err := ts.decideOnAction(ctx, sd, accessToken, tokenID)
	if err != nil {
		return err
	}

	// call appropriate action
	switch resp.Action {
	case ActionSetTelemetryConfig:
		subStatus, err := ts.fleetAPISvc.GetTelemetrySubscriptionStatus(ctx, accessToken, sd.Vin)
		if err != nil {
			ts.logger.Err(err).Msg("Error checking telemetry subscription status")
			return fmt.Errorf("%w: %s", core.ErrTelemetryConfigFailed, err.Error())
		}

		// Log the subscription status for debugging
		ts.logger.Debug().
			Interface("subStatus", subStatus).
			Str("vin", sd.Vin).
			Msg("Fetched telemetry subscription status")

		if subStatus.LimitReached {
			return core.ErrTelemetryLimitReached
		}

		if err := ts.fleetAPISvc.SubscribeForTelemetryData(ctx, accessToken, sd.Vin); err != nil {
			ts.logger.Err(err).Msg("Error registering for telemetry")
			return fmt.Errorf("%w: %s", core.ErrTelemetryConfigFailed, err.Error())
		}

	case ActionStartPolling:
		startErr := ts.devicesSvc.StartTeslaTask(ctx, tokenID)
		if startErr != nil {
			ts.logger.Warn().Err(startErr).Msg("Failed to start Tesla task for synthetic device.")
		}

	default:
		return core.ErrTelemetryNotReady
	}

	return nil
}

// decideOnAction determines the next action for a Tesla vehicle based on its fleet status.
// It retrieves the vehicle's connection status and evaluates the appropriate action using a decision tree.
func (ts *TeslaService) decideOnAction(ctx context.Context, sd *dbmodels.SyntheticDevice, accessToken string, tokenID int64) (*models.StatusDecision, error) {
	// get vehicle status
	connectionStatus, err := ts.fleetAPISvc.VirtualKeyConnectionStatus(ctx, accessToken, sd.Vin)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", core.ErrFleetStatusCheck, err.Error())
	}

	ts.logger.Debug().
		Interface("connectionStatus", connectionStatus).
		Str("vin", sd.Vin).
		Msg("Fetched virtual key connection status")

	// determine action based on status
	resp, err := DecisionTreeAction(connectionStatus, tokenID)
	if err != nil {
		ts.logger.Err(err)
		return nil, fmt.Errorf("error determining fleet action: %w", err)
	}
	return resp, nil
}
