package repository

import (
	"context"

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

// Repositories aggregates all repository interfaces
type Repositories struct {
	Credential CredentialRepository
}
