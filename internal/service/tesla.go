package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/models"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/rs/zerolog"
	"github.com/volatiletech/null/v8"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"regexp"
	"strconv"
)

type TeslaService struct {
	settings *config.Settings
	logger   *zerolog.Logger
	Cipher   cipher.Cipher
	pdb      *db.Store
}

func NewTeslaService(settings *config.Settings, logger *zerolog.Logger, cipher cipher.Cipher, pdb *db.Store) *TeslaService {
	return &TeslaService{
		settings: settings,
		logger:   logger,
		Cipher:   cipher,
		pdb:      pdb,
	}
}

// GetVehicleByVIN retrieves a vehicle by its VIN.
func (ts *TeslaService) GetVehicleByVIN(ctx context.Context, logger *zerolog.Logger, pdb *db.Store, vin string) (*dbmodels.SyntheticDevice, error) {
	tx, err := pdb.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to begin transaction for vehicle %s", vin)
		return nil, err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				logger.Error().Err(rbErr).Msgf("GetVehicleByVIN: Failed to rollback transaction for vehicle %s", vin)
			}
		} else {
			if cmErr := tx.Commit(); cmErr != nil {
				logger.Error().Err(cmErr).Msgf("GetVehicleByVIN: Failed to commit transaction for vehicle %s", vin)
			}
		}
	}()

	sd, err := dbmodels.SyntheticDevices(
		dbmodels.SyntheticDeviceWhere.Vin.EQ(vin)).One(ctx, tx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVehicleNotFound
		}
		logger.Error().Err(err).Msgf("Failed to check if vehicle %s has been processed", vin)
		return nil, err
	}

	return sd, nil
}

// GetByVehicleTokenID retrieves a vehicle by its VIN.
func (ts *TeslaService) GetByVehicleTokenID(ctx context.Context, logger *zerolog.Logger, pdb *db.Store, tokenID int64) (*dbmodels.SyntheticDevice, error) {
	tx, err := pdb.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to begin transaction for vehicle %d", tokenID)
		return nil, err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				logger.Error().Err(rbErr).Msgf("GetVehicleByVIN: Failed to rollback transaction for vehicle %d", tokenID)
			}
		} else {
			if cmErr := tx.Commit(); cmErr != nil {
				logger.Error().Err(cmErr).Msgf("GetVehicleByVIN: Failed to commit transaction for vehicle %d", tokenID)
			}
		}
	}()

	sd, err := dbmodels.SyntheticDevices(
		dbmodels.SyntheticDeviceWhere.VehicleTokenID.EQ(null.IntFrom(int(tokenID)))).One(ctx, tx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVehicleNotFound
		}
		logger.Error().Err(err).Msgf("Failed to check if vehicle %d has been processed", tokenID)
		return nil, err
	}

	return sd, nil
}

// UpdateSubscriptionStatus updates the subscription status of the given SyntheticDevice.
func (ts *TeslaService) UpdateSubscriptionStatus(ctx context.Context, synthDevice *dbmodels.SyntheticDevice, status string) error {
	tx, err := ts.pdb.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		ts.logger.Error().Err(err).Msg("Failed to begin transaction for updating subscription status.")
		return err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				ts.logger.Error().Err(rbErr).Msg("Failed to rollback transaction for updating subscription status.")
			}
		} else {
			if cmErr := tx.Commit(); cmErr != nil {
				ts.logger.Error().Err(cmErr).Msg("Failed to commit transaction for updating subscription status.")
			}
		}
	}()

	// Update subscription status
	synthDevice.SubscriptionStatus = null.String{String: status, Valid: true}

	// Save the changes to the database
	_, err = synthDevice.Update(ctx, tx, boil.Infer())
	if err != nil {
		ts.logger.Error().Err(err).Msg("Failed to update synthetic device subscription status.")
		return err
	}

	return nil
}

// UpdateCreds stores the given credential for the given synthDevice.
// This function encrypts the access and refresh tokens before saving them to the database.
func (tc *TeslaService) UpdateCreds(c context.Context, synthDevice *dbmodels.SyntheticDevice, creds *Credential) error {

	encryptedAccess, err := tc.Cipher.Encrypt(creds.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt access token: %w", err)
	}

	encryptedRefresh, err := tc.Cipher.Encrypt(creds.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt access token: %w", err)
	}

	// store encrypted credentials
	synthDevice.AccessToken = null.String{String: encryptedAccess, Valid: true}
	synthDevice.AccessExpiresAt = null.TimeFrom(creds.AccessExpiry)
	synthDevice.RefreshToken = null.String{String: encryptedRefresh, Valid: true}
	synthDevice.RefreshExpiresAt = null.TimeFrom(creds.RefreshExpiry)

	// Save the changes to the database
	// todo add transaction handling
	_, err = synthDevice.Update(c, tc.pdb.DBS().Writer, boil.Infer())
	if err != nil {
		return err
	}

	return nil
}

func DecisionTreeAction(fleetStatus *VehicleFleetStatus, vehicleTokenID int64) (*models.StatusDecisionResponse, error) {
	var action models.StatusDecisionAction
	var message string
	var next *models.NextAction

	if fleetStatus.VehicleCommandProtocolRequired {
		if fleetStatus.KeyPaired {
			action = models.ActionSetTelemetryConfig
			message = "Vehicle stream compatible. Subscribe to telemetry to enable streaming."
			next = &models.NextAction{
				Method:   "POST",
				Endpoint: fmt.Sprintf("/v1/tesla/telemetry/subscribe/%d", vehicleTokenID),
			}
		} else {
			action = models.ActionOpenTeslaDeeplink
			message = "Virtual key not paired. Open Tesla app deeplink for pairing."
		}
	} else {
		meetsFirmware, err := IsFirmwareFleetTelemetryCapable(fleetStatus.FirmwareVersion)
		if err != nil {
			return nil, fmt.Errorf("unexpected firmware version format %q: %w", fleetStatus.FirmwareVersion, err)
		}
		if !meetsFirmware {
			action = models.ActionUpdateFirmware
			message = "Firmware too old. Please update to 2025.20 or higher."
		} else {
			if fleetStatus.SafetyScreenStreamingToggleEnabled == nil {
				action = models.ActionStartPolling
				message = "Streaming toggle not present. Start polling vehicle telemetry."
				next = &models.NextAction{
					Method:   "POST",
					Endpoint: fmt.Sprintf("/v1/tesla/telemetry/subscribe/%d", vehicleTokenID),
				}
			} else if *fleetStatus.SafetyScreenStreamingToggleEnabled {
				action = models.ActionSetTelemetryConfig
				message = "Vehicle stream compatible. Subscribe to telemetry to enable streaming."
				next = &models.NextAction{
					Method:   "POST",
					Endpoint: fmt.Sprintf("/v1/tesla/telemetry/subscribe/%d", vehicleTokenID),
				}
			} else {
				action = models.ActionPromptToggle
				message = "Streaming toggle disabled. Prompt user to enable it."
			}
		}
	}

	return &models.StatusDecisionResponse{
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
