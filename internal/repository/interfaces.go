package repository

import (
	"context"

	"github.com/DIMO-Network/tesla-oracle/internal/service"
	"github.com/ethereum/go-ethereum/common"
)

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
	Credential CredentialRepository
}
