package repository

import (
	"context"

	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/ethereum/go-ethereum/common"
)

// CredentialRepository handles credential storage operations
type CredentialRepository interface {
	Store(ctx context.Context, user common.Address, cred *Credential) error
	Retrieve(ctx context.Context, user common.Address) (*Credential, error)
	RetrieveAndDelete(ctx context.Context, user common.Address) (*Credential, error)
	RetrieveWithTokensEncrypted(ctx context.Context, user common.Address) (*Credential, error)
	EncryptTokens(cred *Credential) (*Credential, error)
}

// VehicleRepository handles SyntheticDevice data operations (moved from TeslaService)
type VehicleRepository interface {
	GetSyntheticDeviceByVIN(ctx context.Context, vin string) (*dbmodels.SyntheticDevice, error)
	GetSyntheticDeviceByTokenID(ctx context.Context, tokenID int64) (*dbmodels.SyntheticDevice, error)
	GetSyntheticDeviceByAddress(ctx context.Context, address common.Address) (*dbmodels.SyntheticDevice, error)
	UpdateSyntheticDeviceSubscriptionStatus(ctx context.Context, device *dbmodels.SyntheticDevice, status string) error
	UpdateSyntheticDeviceCredentials(ctx context.Context, device *dbmodels.SyntheticDevice, creds *Credential) error
	InsertSyntheticDevice(ctx context.Context, device *dbmodels.SyntheticDevice) error
}

// OnboardingRepository handles onboarding data operations (moved from OnboardingService)
type OnboardingRepository interface {
	GetVehicleByVin(ctx context.Context, vin string) (*dbmodels.Onboarding, error)
	GetVehiclesByVins(ctx context.Context, vins []string) (dbmodels.OnboardingSlice, error)
	GetVehiclesByVinsAndOnboardingStatus(ctx context.Context, vins []string, status int) (dbmodels.OnboardingSlice, error)
	GetVehiclesByVinsAndOnboardingStatusRange(ctx context.Context, vins []string, minStatus, maxStatus int, additionalStatuses []int) (dbmodels.OnboardingSlice, error)
	GetVehicleByExternalID(ctx context.Context, externalID string) (*dbmodels.Onboarding, error)
	InsertVinToDB(ctx context.Context, vin *dbmodels.Onboarding) error
	InsertOrUpdateVin(ctx context.Context, vin *dbmodels.Onboarding) error
	GetVinsByTokenIDs(ctx context.Context, tokenIDs []int64) (dbmodels.OnboardingSlice, error)
	GetVehiclesFromDB(ctx context.Context) (dbmodels.OnboardingSlice, error)
	DeleteOnboarding(ctx context.Context, record *dbmodels.Onboarding) error
	DeleteAll(ctx context.Context) error
}

// Repositories aggregates all repository interfaces
type Repositories struct {
	Vehicle    VehicleRepository
	Credential CredentialRepository
	Onboarding OnboardingRepository
}
