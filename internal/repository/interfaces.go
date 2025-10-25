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

// VehicleRepository handles SyntheticDevice data operations
type VehicleRepository interface {
	GetSyntheticDeviceByVin(ctx context.Context, vin string) (*dbmodels.SyntheticDevice, error)
	GetSyntheticDevicesByVins(ctx context.Context, vins []string) (dbmodels.SyntheticDeviceSlice, error)
	GetSyntheticDeviceByTokenID(ctx context.Context, tokenID int64) (*dbmodels.SyntheticDevice, error)
	GetSyntheticDeviceByAddress(ctx context.Context, address common.Address) (*dbmodels.SyntheticDevice, error)
	UpdateSyntheticDeviceSubscriptionStatus(ctx context.Context, device *dbmodels.SyntheticDevice, status string) error
	UpdateSyntheticDeviceCredentials(ctx context.Context, device *dbmodels.SyntheticDevice, creds *Credential) error
	InsertSyntheticDevice(ctx context.Context, device *dbmodels.SyntheticDevice) error
	DeleteSyntheticDevice(ctx context.Context, address []byte) error
}

// OnboardingRepository handles onboarding data operations
type OnboardingRepository interface {
	GetOnboardingByVin(ctx context.Context, vin string) (*dbmodels.Onboarding, error)
	GetOnboardingsByVins(ctx context.Context, vins []string) (dbmodels.OnboardingSlice, error)
	GetOnboardingsByVinsAndStatus(ctx context.Context, vins []string, status int) (dbmodels.OnboardingSlice, error)
	GetOnboardingsByVinsAndStatusRange(ctx context.Context, vins []string, minStatus, maxStatus int, additionalStatuses []int) (dbmodels.OnboardingSlice, error)
	GetOnboardingByExternalID(ctx context.Context, externalID string) (*dbmodels.Onboarding, error)
	InsertOnboarding(ctx context.Context, vin *dbmodels.Onboarding) error
	InsertOrUpdateOnboarding(ctx context.Context, vin *dbmodels.Onboarding) error
	GetOnboardingsByTokenIDs(ctx context.Context, tokenIDs []int64) (dbmodels.OnboardingSlice, error)
	GetOnboardings(ctx context.Context) (dbmodels.OnboardingSlice, error)
	DeleteOnboarding(ctx context.Context, record *dbmodels.Onboarding) error
	DeleteAllOnboardings(ctx context.Context) error
}

// CommandRepository handles device command request operations
type CommandRepository interface {
	SaveCommandRequest(ctx context.Context, request *dbmodels.DeviceCommandRequest) error
	UpdateCommandRequest(ctx context.Context, request *dbmodels.DeviceCommandRequest) error
	GetCommandRequest(ctx context.Context, taskID string) (*dbmodels.DeviceCommandRequest, error)
	GetCommandRequestsByVehicle(ctx context.Context, vehicleTokenID int, limit int) (dbmodels.DeviceCommandRequestSlice, error)
}

// Repositories aggregates all repository interfaces
type Repositories struct {
	Vehicle    VehicleRepository
	Credential CredentialRepository
	Onboarding OnboardingRepository
	Command    CommandRepository
}
