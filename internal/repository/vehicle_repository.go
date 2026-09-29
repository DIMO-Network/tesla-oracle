package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/shared/pkg/db"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/aarondl/sqlboiler/v4/queries/qm"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
)

var (
	ErrVehicleNotFound = errors.New("vehicle not found")
	// ErrVehicleAlreadyConnected: the vehicle already has a synthetic device row
	// with a minted SD, so onboarding can't store another one for it.
	ErrVehicleAlreadyConnected = errors.New("vehicle already has a connected synthetic device")
)

type vehicleRepository struct {
	db     *db.Store
	cipher cipher.Cipher
	logger *zerolog.Logger
}

func NewVehicleRepository(db *db.Store, cipher cipher.Cipher, logger *zerolog.Logger) VehicleRepository {
	return &vehicleRepository{
		db:     db,
		cipher: cipher,
		logger: logger,
	}
}

// GetSyntheticDeviceByVin retrieves a synthetic device by its VIN
func (r *vehicleRepository) GetSyntheticDeviceByVin(ctx context.Context, vin string) (*dbmodels.SyntheticDevice, error) {
	sd, err := dbmodels.SyntheticDevices(dbmodels.SyntheticDeviceWhere.Vin.EQ(vin)).One(ctx, r.db.DBS().Reader)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVehicleNotFound
		}
		return nil, fmt.Errorf("failed to query vehicle with VIN %s: %w", vin, err)
	}
	return sd, nil
}

// GetSyntheticDevicesByVIN retrieves all fully minted synthetic devices for a VIN.
func (r *vehicleRepository) GetSyntheticDevicesByVIN(ctx context.Context, vin string) (dbmodels.SyntheticDeviceSlice, error) {
	devices, err := dbmodels.SyntheticDevices(
		dbmodels.SyntheticDeviceWhere.Vin.EQ(vin),
		dbmodels.SyntheticDeviceWhere.VehicleTokenID.IsNotNull(),
		dbmodels.SyntheticDeviceWhere.TokenID.IsNotNull(),
	).All(ctx, r.db.DBS().Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to query synthetic devices for VIN %s: %w", vin, err)
	}

	return devices, nil
}

// GetSyntheticDevicesByVins retrieves all synthetic devices matching the provided VINs
func (r *vehicleRepository) GetSyntheticDevicesByVins(ctx context.Context, vins []string) (dbmodels.SyntheticDeviceSlice, error) {
	if len(vins) == 0 {
		return dbmodels.SyntheticDeviceSlice{}, nil
	}

	devices, err := dbmodels.SyntheticDevices(
		dbmodels.SyntheticDeviceWhere.Vin.IN(vins),
	).All(ctx, r.db.DBS().Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to query vehicles with VINs: %w", err)
	}

	return devices, nil
}

// GetSyntheticDevicesBySubscriptionStatus retrieves all synthetic devices for a subscription status.
func (r *vehicleRepository) GetSyntheticDevicesBySubscriptionStatus(ctx context.Context, status string) (dbmodels.SyntheticDeviceSlice, error) {
	devices, err := dbmodels.SyntheticDevices(
		dbmodels.SyntheticDeviceWhere.SubscriptionStatus.EQ(null.StringFrom(status)),
		dbmodels.SyntheticDeviceWhere.VehicleTokenID.IsNotNull(),
		dbmodels.SyntheticDeviceWhere.TokenID.IsNotNull(),
	).All(ctx, r.db.DBS().Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to query synthetic devices with subscription status %s: %w", status, err)
	}

	return devices, nil
}

// GetSyntheticDeviceByTokenID retrieves a synthetic device by its token ID
func (r *vehicleRepository) GetSyntheticDeviceByTokenID(ctx context.Context, tokenID int64) (*dbmodels.SyntheticDevice, error) {
	sd, err := dbmodels.SyntheticDevices(
		dbmodels.SyntheticDeviceWhere.VehicleTokenID.EQ(null.IntFrom(int(tokenID)))).One(ctx, r.db.DBS().Reader)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVehicleNotFound
		}
		return nil, fmt.Errorf("failed to check if vehicle with token ID %d has been processed: %w", tokenID, err)
	}
	return sd, nil
}

// GetSyntheticDeviceByAddress retrieves a synthetic device by its address
func (r *vehicleRepository) GetSyntheticDeviceByAddress(ctx context.Context, address common.Address) (*dbmodels.SyntheticDevice, error) {
	device, err := dbmodels.SyntheticDevices(
		dbmodels.SyntheticDeviceWhere.Address.EQ(address.Bytes())).One(ctx, r.db.DBS().Reader)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVehicleNotFound
		}
		return nil, fmt.Errorf("failed to find synthetic device by address: %w", err)
	}
	return device, nil
}

// UpdateSyntheticDeviceSubscriptionStatus updates the subscription status of a synthetic device.
// It writes only that column: the rest of synthDevice may be stale, and writing
// it back would undo concurrent changes, such as a burn clearing the credentials.
func (r *vehicleRepository) UpdateSyntheticDeviceSubscriptionStatus(ctx context.Context, synthDevice *dbmodels.SyntheticDevice, status string) error {
	synthDevice.SubscriptionStatus = null.String{String: status, Valid: true}

	_, err := synthDevice.Update(ctx, r.db.DBS().Writer, boil.Whitelist(dbmodels.SyntheticDeviceColumns.SubscriptionStatus))
	if err != nil {
		r.logger.Error().Err(err).Msg("Failed to update synthetic device subscription status.")
		return err
	}

	return nil
}

// UpdateSyntheticDeviceCredentials updates the credentials for a synthetic device
func (r *vehicleRepository) UpdateSyntheticDeviceCredentials(ctx context.Context, synthDevice *dbmodels.SyntheticDevice, creds *Credential) error {
	encryptedAccess, err := r.cipher.Encrypt(creds.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt access token: %w", err)
	}

	encryptedRefresh, err := r.cipher.Encrypt(creds.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt refresh token: %w", err)
	}

	// store encrypted credentials
	synthDevice.AccessToken = null.String{String: encryptedAccess, Valid: true}
	synthDevice.AccessExpiresAt = null.TimeFrom(creds.AccessExpiry)
	synthDevice.RefreshToken = null.String{String: encryptedRefresh, Valid: true}
	synthDevice.RefreshExpiresAt = null.TimeFrom(creds.RefreshExpiry)

	// Save the changes to the database
	// TODO: add transaction handling
	_, err = synthDevice.Update(ctx, r.db.DBS().Writer, boil.Infer())
	if err != nil {
		return err
	}

	return nil
}

// InsertSyntheticDevice inserts a new synthetic device record into the database
func (r *vehicleRepository) InsertSyntheticDevice(ctx context.Context, device *dbmodels.SyntheticDevice) error {
	err := device.Insert(ctx, r.db.DBS().Writer, boil.Infer())
	if err != nil {
		r.logger.Error().Err(err).Msg("Failed to insert synthetic device")
		return fmt.Errorf("failed to insert synthetic device: %w", err)
	}
	return nil
}

// CompleteOnboarding stores the synthetic device of a finished onboarding and
// deletes its onboarding record, in one transaction, so a failure leaves both as
// they were and the finalize can be retried.
//
// If the vehicle has a disconnected row (its SD burned), that row is updated in
// place: its subscription status and the command history that references it stay.
// It reports whether it reconnected such a row.
func (r *vehicleRepository) CompleteOnboarding(ctx context.Context, device *dbmodels.SyntheticDevice, onboarding *dbmodels.Onboarding) (reconnected bool, err error) {
	tx, err := r.db.DBS().Writer.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	existing, err := dbmodels.SyntheticDevices(
		dbmodels.SyntheticDeviceWhere.VehicleTokenID.EQ(device.VehicleTokenID),
		qm.For("UPDATE"),
	).One(ctx, tx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if err = device.Insert(ctx, tx, boil.Infer()); err != nil {
			return false, fmt.Errorf("failed to insert synthetic device: %w", err)
		}
	case err != nil:
		return false, fmt.Errorf("failed to look up the vehicle's synthetic device: %w", err)
	case existing.TokenID.Valid:
		err = fmt.Errorf("%w: vehicle %d, synthetic device %d", ErrVehicleAlreadyConnected, existing.VehicleTokenID.Int, existing.TokenID.Int)
		return false, err
	default:
		// The address is the primary key, so this can't go through the model's Update.
		_, err = dbmodels.SyntheticDevices(dbmodels.SyntheticDeviceWhere.Address.EQ(existing.Address)).UpdateAll(ctx, tx, dbmodels.M{
			dbmodels.SyntheticDeviceColumns.Address:           device.Address,
			dbmodels.SyntheticDeviceColumns.Vin:               device.Vin,
			dbmodels.SyntheticDeviceColumns.TokenID:           device.TokenID,
			dbmodels.SyntheticDeviceColumns.WalletChildNumber: device.WalletChildNumber,
			dbmodels.SyntheticDeviceColumns.AccessToken:       device.AccessToken,
			dbmodels.SyntheticDeviceColumns.AccessExpiresAt:   device.AccessExpiresAt,
			dbmodels.SyntheticDeviceColumns.RefreshToken:      device.RefreshToken,
			dbmodels.SyntheticDeviceColumns.RefreshExpiresAt:  device.RefreshExpiresAt,
		})
		if err != nil {
			return false, fmt.Errorf("failed to reconnect synthetic device: %w", err)
		}
		reconnected = true
	}

	if _, err = onboarding.Delete(ctx, tx); err != nil {
		return false, fmt.Errorf("failed to delete onboarding record: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return false, fmt.Errorf("failed to commit onboarding: %w", err)
	}

	return reconnected, nil
}

// DeleteSyntheticDevice deletes a synthetic device by its address (primary key)
// Used during reconnection to remove the old disconnected device before inserting the new one
func (r *vehicleRepository) DeleteSyntheticDevice(ctx context.Context, address []byte) error {
	device, err := dbmodels.SyntheticDevices(
		dbmodels.SyntheticDeviceWhere.Address.EQ(address),
	).One(ctx, r.db.DBS().Reader)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrVehicleNotFound
		}
		return fmt.Errorf("failed to find synthetic device for deletion: %w", err)
	}

	_, err = device.Delete(ctx, r.db.DBS().Writer)
	if err != nil {
		r.logger.Error().Err(err).Msg("Failed to delete synthetic device")
		return fmt.Errorf("failed to delete synthetic device: %w", err)
	}

	r.logger.Info().Str("vin", device.Vin).Msg("Successfully deleted disconnected synthetic device")
	return nil
}
