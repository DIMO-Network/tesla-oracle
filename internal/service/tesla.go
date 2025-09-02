package service

import (
	"context"
	"fmt"
	"strconv"
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
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"regexp"
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

func DecisionTreeAction(fleetStatus *VehicleFleetStatus, vehicleTokenID int64) (*models.StatusDecision, error) {
	var action string
	var message string
	var next *models.NextAction

	if fleetStatus.VehicleCommandProtocolRequired {
		if fleetStatus.KeyPaired {
			action = models.ActionSetTelemetryConfig
			message = models.MessageReadyToStartDataFlow
			next = &models.NextAction{
				Method:   "POST",
				Endpoint: fmt.Sprintf("/v1/tesla/%d/start", vehicleTokenID),
			}
		} else {
			action = models.ActionOpenTeslaDeeplink
			message = models.MessageVirtualKeyNotPaired
		}
	} else {
		meetsFirmware, err := IsFirmwareFleetTelemetryCapable(fleetStatus.FirmwareVersion)
		if err != nil {
			return nil, fmt.Errorf("unexpected firmware version format %q: %w", fleetStatus.FirmwareVersion, err)
		}
		if !meetsFirmware {
			action = models.ActionUpdateFirmware
			message = models.MessageFirmwareTooOld
		} else {
			if fleetStatus.SafetyScreenStreamingToggleEnabled == nil {
				action = models.ActionStartPolling
				message = models.MessageReadyToStartDataFlow
				next = &models.NextAction{
					Method:   "POST",
					Endpoint: fmt.Sprintf("/v1/tesla/%d/start", vehicleTokenID),
				}
			} else if *fleetStatus.SafetyScreenStreamingToggleEnabled {
				action = models.ActionSetTelemetryConfig
				message = models.MessageReadyToStartDataFlow
				next = &models.NextAction{
					Method:   "POST",
					Endpoint: fmt.Sprintf("/v1/tesla/%d/start", vehicleTokenID),
				}
			} else {
				action = models.ActionPromptToggle
				message = models.MessageStreamingToggleDisabled
			}
		}
	}

	return &models.StatusDecision{
		Action:  action,
		Message: message,
		Next:    next,
	}, nil
}

func IsFleetTelemetryCapable(fs *VehicleFleetStatus) bool {
	// We used to check for the presence of a meaningful value (not ""
	// or "unknown") for fleet_telemetry_version, but this started
	// populating on old cars that are not capable of streaming.
	return fs.VehicleCommandProtocolRequired || !fs.DiscountedDeviceData
}

var teslaFirmwareStart = regexp.MustCompile(`^(\d{4})\.(\d+)`)

func IsFirmwareFleetTelemetryCapable(v string) (bool, error) {
	m := teslaFirmwareStart.FindStringSubmatch(v)
	if len(m) != 3 {
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

	return year > 2025 || (year == 2025 && week >= 20), nil
}

// FetchVehicle retrieves a vehicle from identity-api by its token ID.
func (ts *TeslaService) FetchVehicle(vehicleTokenId int64) (*models.Vehicle, error) {
	vehicle, err := ts.identitySvc.FetchVehicleByTokenID(vehicleTokenId)
	if err != nil {
		ts.logger.Err(err).Msg("Failed to fetch vehicle by token ID.")
		return nil, fiber.NewError(fiber.StatusInternalServerError, "Failed to fetch vehicle information.")
	}

	if vehicle == nil || vehicle.Owner == "" || vehicle.SyntheticDevice.Address == "" {
		ts.logger.Warn().Msg("Vehicle not found or owner information or synthetic device address is missing.")
		return nil, fiber.NewError(fiber.StatusNotFound, "Vehicle not found or owner information or synthetic device address is missing.")
	}
	return vehicle, nil
}

// DecodeTeslaVIN decodes a Tesla VIN to get device definition information.
func (ts *TeslaService) DecodeTeslaVIN(vin string) (*models.DeviceDefinition, error) {
	decodeVIN, err := ts.ddSvc.DecodeVin(vin, "USA")
	if err != nil {
		return nil, err
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

	return nil, errors.New("device definition not found")
}

// GetOrRefreshAccessToken checks if the access token for the given synthetic device has expired.
// If the access token is expired and the refresh token is still valid, it attempts to refresh the access token.
// If the refresh token is expired, it returns an unauthorized error.
func (ts *TeslaService) GetOrRefreshAccessToken(ctx context.Context, sd *dbmodels.SyntheticDevice) (string, error) {
	accessToken, err := ts.Cipher.Decrypt(sd.AccessToken.String)
	if err != nil {
		return "", fiber.NewError(fiber.StatusInternalServerError, "Failed to decrypt access token.")
	}

	if !sd.AccessExpiresAt.IsZero() && time.Now().After(sd.AccessExpiresAt.Time) {
		refreshToken, err := ts.Cipher.Decrypt(sd.RefreshToken.String)
		if err != nil {
			return "", fiber.NewError(fiber.StatusInternalServerError, "Failed to decrypt refresh token.")
		}
		if !sd.RefreshExpiresAt.IsZero() && time.Now().Before(sd.RefreshExpiresAt.Time) {
			tokens, errRefresh := ts.fleetAPISvc.RefreshToken(ctx, refreshToken)
			if errRefresh != nil {
				return "", fiber.NewError(fiber.StatusInternalServerError, "Failed to refresh access token.")
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
			return "", fiber.NewError(fiber.StatusUnauthorized, "Refresh token has expired. Please reauthenticate.")
		}
	}

	return accessToken, nil
}

// StartStreamingOrPolling determines whether to start streaming telemetry data or polling for a Tesla vehicle.
// It checks if the vehicle has valid credentials, refreshes the access token if necessary, and decides the next action.
func (ts *TeslaService) StartStreamingOrPolling(ctx context.Context, sd *dbmodels.SyntheticDevice, tokenID int64) error {
	// check if we have access token
	if sd == nil || sd.AccessToken.String == "" || sd.RefreshToken.String == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "No credentials found for vehicle. Please reauthenticate.")
	}

	accessToken, err := ts.GetOrRefreshAccessToken(ctx, sd)
	if err != nil {
		return err
	}

	resp, err := ts.DecideOnAction(ctx, sd, accessToken, tokenID)
	if err != nil {
		return err
	}

	// call appropriate action
	switch resp.Action {
	case models.ActionSetTelemetryConfig:
		subStatus, err := ts.fleetAPISvc.GetTelemetrySubscriptionStatus(ctx, accessToken, sd.Vin)
		if err != nil {
			ts.logger.Err(err).Msg("Error checking telemetry subscription status")
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to check telemetry subscription status.")
		}
		if subStatus.LimitReached {
			return fiber.NewError(fiber.StatusConflict, "Telemetry subscription limit reached. Vehicle has reached max supported applications and new fleet telemetry requests cannot be added to the vehicle.")
		}

		if err := ts.fleetAPISvc.SubscribeForTelemetryData(ctx, accessToken, sd.Vin); err != nil {
			ts.logger.Err(err).Msg("Error registering for telemetry")
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to update telemetry configuration.")
		}

	case models.ActionStartPolling:
		startErr := ts.devicesSvc.StartTeslaTask(ctx, tokenID)
		if startErr != nil {
			ts.logger.Warn().Err(startErr).Msg("Failed to start Tesla task for synthetic device.")
		}

	default:
		return fiber.NewError(fiber.StatusConflict, "Vehicle is not ready for telemetry subscription. Call GetStatus endpoint to determine next steps.")
	}

	return nil
}

// DecideOnAction determines the next action for a Tesla vehicle based on its fleet status.
// It retrieves the vehicle's connection status and evaluates the appropriate action using a decision tree.
func (ts *TeslaService) DecideOnAction(ctx context.Context, sd *dbmodels.SyntheticDevice, accessToken string, tokenID int64) (*models.StatusDecision, error) {
	// get vehicle status
	connectionStatus, err := ts.fleetAPISvc.VirtualKeyConnectionStatus(ctx, accessToken, sd.Vin)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusInternalServerError, "Error checking fleet status.")
	}

	// determine action based on status
	resp, err := DecisionTreeAction(connectionStatus, tokenID)
	if err != nil {
		ts.logger.Err(err)
		return nil, fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("Error determining fleet action: %s", err.Error()))
	}
	return resp, nil
}

// ValidateVehicleOwnership checks if the vehicle belongs to the authenticated user.
func (ts *TeslaService) ValidateVehicleOwnership(tokenID int64, walletAddress common.Address) error {
	vehicle, err := ts.FetchVehicle(tokenID)
	if err != nil {
		return err
	}

	if vehicle == nil || vehicle.Owner != walletAddress.Hex() {
		return fiber.NewError(fiber.StatusUnauthorized, "Vehicle does not belong to the authenticated user.")
	}

	return nil
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
		return fiber.NewError(fiber.StatusUnauthorized, fmt.Sprintf("Dev license %s is not allowed to subscribe to telemetry.", walletAddress.Hex()))
	}

	// Get synthetic device
	sd, err := ts.repositories.Vehicle.GetSyntheticDeviceByTokenID(ctx, tokenID)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Failed to get vehicle by vehicle token id.")
	}

	// Start streaming or polling
	err = ts.StartStreamingOrPolling(ctx, sd, tokenID)
	if err != nil {
		return err
	}

	// Update subscription status
	err = ts.repositories.Vehicle.UpdateSyntheticDeviceSubscriptionStatus(ctx, sd, "active")
	if err != nil {
		ts.logger.Err(err).Msg("Failed to update subscription status.")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to update subscription status.")
	}

	return nil
}

// StartVehicleDataFlow handles the complete data flow startup workflow
func (ts *TeslaService) StartVehicleDataFlow(ctx context.Context, tokenID int64, walletAddress common.Address) error {
	// Validate vehicle ownership
	err := ts.ValidateVehicleOwnership(tokenID, walletAddress)
	if err != nil {
		return err
	}

	// Get synthetic device
	sd, err := ts.repositories.Vehicle.GetSyntheticDeviceByTokenID(ctx, tokenID)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Failed to get vehicle by token ID.")
	}

	// Start streaming or polling
	return ts.StartStreamingOrPolling(ctx, sd, tokenID)
}

// UnsubscribeFromTelemetry handles the complete telemetry unsubscription workflow
func (ts *TeslaService) UnsubscribeFromTelemetry(ctx context.Context, tokenID int64, walletAddress common.Address) error {
	// Validate dev license
	if walletAddress != ts.settings.MobileAppDevLicense {
		return fiber.NewError(fiber.StatusUnauthorized, fmt.Sprintf("Dev license %s is not allowed to unsubscribe from telemetry.", walletAddress.Hex()))
	}

	// Get partners token
	partnersTokenResp, err := ts.fleetAPISvc.GetPartnersToken(ctx)
	if err != nil {
		ts.logger.Err(err).Msg("Failed to get partners token.")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to get partners token.")
	}

	if partnersTokenResp.AccessToken == "" {
		return fiber.NewError(fiber.StatusInternalServerError, "Partners token response did not contain an access token.")
	}

	// Fetch vehicle
	vehicle, err := ts.FetchVehicle(tokenID)
	if err != nil {
		return err
	}

	// Get synthetic device
	device, err := ts.repositories.Vehicle.GetSyntheticDeviceByAddress(ctx, common.HexToAddress(vehicle.SyntheticDevice.Address))
	if err != nil {
		ts.logger.Err(err).Msg("Failed to find synthetic device.")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to find synthetic device.")
	}

	// Unsubscribe from telemetry data
	err = ts.fleetAPISvc.UnSubscribeFromTelemetryData(ctx, partnersTokenResp.AccessToken, device.Vin)
	if err != nil {
		ts.logger.Err(err).Str("vin", device.Vin).Msg("Failed to unsubscribe from telemetry data")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to unsubscribe from telemetry data")
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
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to update subscription status.")
	}

	return nil
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
		return nil, fmt.Errorf("error persisting credentials: %w", err)
	}

	// Get vehicle list from Tesla
	vehicles, err := ts.fleetAPISvc.GetVehicles(ctx, teslaAuth.AccessToken)
	if err != nil {
		if errors.Is(err, ErrWrongRegion) {
			return nil, fiber.NewError(fiber.StatusInternalServerError, "Region detection failed. Waiting on a fix from Tesla.")
		}
		return nil, fiber.NewError(fiber.StatusInternalServerError, "Couldn't fetch vehicles from Tesla.")
	}

	// Process each vehicle
	response := make([]models.TeslaVehicleRes, 0, len(vehicles))
	for _, v := range vehicles {
		// Decode VIN
		ddRes, err := ts.DecodeTeslaVIN(v.VIN)
		if err != nil {
			ts.logger.Err(err).Str("vin", v.VIN).Msg("Failed to decode Tesla VIN.")
			return nil, fiber.NewError(fiber.StatusFailedDependency, "An error occurred completing tesla authorization")
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
				return nil, fiber.NewError(fiber.StatusInternalServerError, "Failed to create onboarding record.")
			}
		}

		// Build response
		response = append(response, models.TeslaVehicleRes{
			ExternalID: strconv.Itoa(v.ID),
			VIN:        v.VIN,
			Definition: models.DeviceDefinition1{
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
	err := ts.ValidateVehicleOwnership(tokenID, walletAddress)
	if err != nil {
		return nil, err
	}

	// Get synthetic device
	sd, err := ts.repositories.Vehicle.GetSyntheticDeviceByTokenID(ctx, tokenID)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusNotFound, "Failed to get vehicle by token ID.")
	}

	// Check if we have access token
	if sd == nil || sd.AccessToken.String == "" || sd.RefreshToken.String == "" {
		return nil, fiber.NewError(fiber.StatusUnauthorized, "No credentials found for vehicle. Please reauthenticate.")
	}

	// Get or refresh access token
	accessToken, err := ts.GetOrRefreshAccessToken(ctx, sd)
	if err != nil {
		return nil, err
	}

	// Get status and decide on action
	return ts.DecideOnAction(ctx, sd, accessToken, tokenID)
}

// GetVirtualKeyStatus handles virtual key status check workflow
func (ts *TeslaService) GetVirtualKeyStatus(ctx context.Context, vin string, walletAddress common.Address) (*models.VirtualKeyStatusResponse, error) {
	// Get credentials from repository
	teslaAuth, err := ts.repositories.Credential.Retrieve(ctx, walletAddress)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusUnauthorized, err.Error())
	}

	// Check fleet status
	fleetStatus, err := ts.fleetAPISvc.VirtualKeyConnectionStatus(ctx, teslaAuth.AccessToken, vin)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusInternalServerError, "Error checking fleet status.")
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
