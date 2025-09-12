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
	accessToken, err := tam.cipher.Decrypt(sd.AccessToken.String)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrCredentialDecryption, err.Error())
	}

	if !sd.AccessExpiresAt.IsZero() && time.Now().After(sd.AccessExpiresAt.Time) {
		refreshToken, err := tam.cipher.Decrypt(sd.RefreshToken.String)
		if err != nil {
			return "", fmt.Errorf("%w: %s", ErrCredentialDecryption, err.Error())
		}
		if !sd.RefreshExpiresAt.IsZero() && time.Now().Before(sd.RefreshExpiresAt.Time) {
			tokens, errRefresh := tam.fleetAPISvc.RefreshToken(ctx, refreshToken)
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
			errUpdate := tam.vehicleRepo.UpdateSyntheticDeviceCredentials(ctx, sd, &creds)
			if errUpdate != nil {
				tam.logger.Warn().Err(errUpdate).Msg("Failed to update credentials after refresh.")
			}
			return tokens.AccessToken, nil
		} else {
			return "", ErrTokenExpired
		}
	}

	return accessToken, nil
}
