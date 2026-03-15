package core

import (
	"context"
	"fmt"
	"time"

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/rs/zerolog"
)

const refreshLeadTime = 5 * time.Minute

// TeslaTokenManager handles Tesla authentication and token operations
type TeslaTokenManager struct {
	cipher      cipher.Cipher
	vehicleRepo repository.VehicleRepository
	fleetAPISvc TeslaFleetAPIService
	logger      *zerolog.Logger
}

// NewTeslaTokenManager creates a new Tesla authentication manager
func NewTeslaTokenManager(
	cipher cipher.Cipher,
	vehicleRepo repository.VehicleRepository,
	fleetAPISvc TeslaFleetAPIService,
	logger *zerolog.Logger,
) *TeslaTokenManager {
	return &TeslaTokenManager{
		cipher:      cipher,
		vehicleRepo: vehicleRepo,
		fleetAPISvc: fleetAPISvc,
		logger:      logger,
	}
}

// GetOrRefreshAccessToken checks if the access token for the given synthetic device has expired.
// If the access token is expired and the refresh token is still valid, it attempts to refresh the access token.
// If the refresh token is expired, it returns an unauthorized error.
func (tam *TeslaTokenManager) GetOrRefreshAccessToken(ctx context.Context, sd *dbmodels.SyntheticDevice) (string, error) {
	if sd == nil || !sd.VehicleTokenID.Valid {
		return "", ErrNoCredentials
	}

	lockedDevice, tx, err := tam.vehicleRepo.GetSyntheticDeviceByTokenIDForUpdate(ctx, int64(sd.VehicleTokenID.Int))
	if err != nil {
		return "", err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	now := time.Now()
	needsRefresh := !lockedDevice.AccessExpiresAt.Valid || now.Add(refreshLeadTime).After(lockedDevice.AccessExpiresAt.Time)

	if !needsRefresh {
		accessToken, err := tam.cipher.Decrypt(lockedDevice.AccessToken.String)
		if err != nil {
			return "", fmt.Errorf("%w: %s", ErrCredentialDecryption, err.Error())
		}
		if err := tx.Commit(); err != nil {
			return "", fmt.Errorf("failed to commit token read transaction: %w", err)
		}
		return accessToken, nil
	}

	refreshToken, err := tam.cipher.Decrypt(lockedDevice.RefreshToken.String)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrCredentialDecryption, err.Error())
	}
	if !lockedDevice.RefreshExpiresAt.Valid || !now.Before(lockedDevice.RefreshExpiresAt.Time) {
		return "", ErrTokenExpired
	}

	tokens, err := tam.fleetAPISvc.RefreshToken(ctx, refreshToken)
	if err != nil {
		tam.logger.Warn().Err(err).Int("vehicleTokenId", lockedDevice.VehicleTokenID.Int).Msg("Failed to refresh token.")
		return "", err
	}

	expiryTime := now.Add(time.Duration(tokens.ExpiresIn) * time.Second)
	creds := repository.Credential{
		AccessToken:   tokens.AccessToken,
		RefreshToken:  tokens.RefreshToken,
		AccessExpiry:  expiryTime,
		RefreshExpiry: now.AddDate(0, 3, 0),
	}
	if err := tam.vehicleRepo.UpdateSyntheticDeviceCredentialsTx(ctx, tx, lockedDevice, &creds); err != nil {
		tam.logger.Warn().Err(err).Msg("Failed to update credentials after refresh.")
		return "", fmt.Errorf("%w: %s", ErrCredentialStore, err.Error())
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("failed to commit token refresh transaction: %w", err)
	}

	return tokens.AccessToken, nil
}
