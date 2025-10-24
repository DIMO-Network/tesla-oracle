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
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
)

var (
	ErrVehicleNotFound = errors.New("vehicle not found")
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

// UpdateSyntheticDeviceSubscriptionStatus updates the subscription status of a synthetic device
func (r *vehicleRepository) UpdateSyntheticDeviceSubscriptionStatus(ctx context.Context, synthDevice *dbmodels.SyntheticDevice, status string) error {
	tx, err := r.db.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		r.logger.Error().Err(err).Msg("Failed to begin transaction for updating subscription status.")
		return err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.logger.Error().Err(rbErr).Msg("Failed to rollback transaction for updating subscription status.")
			}
		} else {
			if cmErr := tx.Commit(); cmErr != nil {
				r.logger.Error().Err(cmErr).Msg("Failed to commit transaction for updating subscription status.")
			}
		}
	}()

	synthDevice.SubscriptionStatus = null.String{String: status, Valid: true}

	_, err = synthDevice.Update(ctx, tx, boil.Infer())
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

// GetDisconnectedDevices retrieves all disconnected synthetic devices
// Disconnected devices have token_id = NULL and vehicle_token_id IS NOT NULL
func (r *vehicleRepository) GetDisconnectedDevices(ctx context.Context) (dbmodels.SyntheticDeviceSlice, error) {
	devices, err := dbmodels.SyntheticDevices(
		dbmodels.SyntheticDeviceWhere.TokenID.IsNull(),
		dbmodels.SyntheticDeviceWhere.VehicleTokenID.IsNotNull(),
	).All(ctx, r.db.DBS().Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to query disconnected vehicles: %w", err)
	}
	return devices, nil
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
