package repository

import (
	"context"

	"github.com/DIMO-Network/tesla-oracle/internal/service"
	"github.com/ethereum/go-ethereum/common"
)

// VehicleRepository handles all Tesla vehicle data operations
type VehicleRepository interface {
	// Core vehicle operations
	GetVehicleByTokenID(ctx context.Context, tokenID int) (*service.TeslaVehicle, error)
	GetVehicleByVIN(ctx context.Context, vin string) (*service.TeslaVehicle, error)
	CreateVehicle(ctx context.Context, vehicle *service.TeslaVehicle) error
	UpdateVehicle(ctx context.Context, vehicle *service.TeslaVehicle) error
	CreateOrUpdateVehicle(ctx context.Context, vehicle *service.TeslaVehicle) error

	// User-specific operations
	GetUserVehicles(ctx context.Context, userAddress common.Address) ([]*service.TeslaVehicle, error)
	GetVehiclesForMinting(ctx context.Context, vins []string, userAddr common.Address) ([]*service.TeslaVehicle, error)
}

// CredentialRepository handles credential storage operations
type CredentialRepository interface {
	Store(ctx context.Context, user common.Address, cred *service.Credential) error
	Retrieve(ctx context.Context, user common.Address) (*service.Credential, error)
	RetrieveAndDelete(ctx context.Context, user common.Address) (*service.Credential, error)
	RetrieveWithTokensEncrypted(ctx context.Context, user common.Address) (*service.Credential, error)
	EncryptTokens(cred *service.Credential) (*service.Credential, error)
}

// Repositories aggregates all repository interfaces
type Repositories struct {
	Vehicle    VehicleRepository
	Credential CredentialRepository
}
