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
}

// Repositories aggregates all repository interfaces
type Repositories struct {
	Vehicle    VehicleRepository
	Credential CredentialRepository
}
