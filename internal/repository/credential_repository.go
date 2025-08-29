package repository

import (
	"context"

	"github.com/DIMO-Network/tesla-oracle/internal/service"
	"github.com/ethereum/go-ethereum/common"
)

// CredStore is the interface that the existing credential store implementations use
type CredStore interface {
	Store(ctx context.Context, user common.Address, cred *service.Credential) error
	Retrieve(ctx context.Context, user common.Address) (*service.Credential, error)
	RetrieveAndDelete(ctx context.Context, user common.Address) (*service.Credential, error)
	RetrieveWithTokensEncrypted(ctx context.Context, user common.Address) (*service.Credential, error)
	EncryptTokens(cred *service.Credential) (*service.Credential, error)
}

type credentialRepository struct {
	store CredStore
}

func NewCredentialRepository(store CredStore) CredentialRepository {
	return &credentialRepository{store: store}
}

func (r *credentialRepository) Store(ctx context.Context, user common.Address, cred *service.Credential) error {
	return r.store.Store(ctx, user, cred)
}

func (r *credentialRepository) Retrieve(ctx context.Context, user common.Address) (*service.Credential, error) {
	return r.store.Retrieve(ctx, user)
}

func (r *credentialRepository) RetrieveAndDelete(ctx context.Context, user common.Address) (*service.Credential, error) {
	return r.store.RetrieveAndDelete(ctx, user)
}

func (r *credentialRepository) RetrieveWithTokensEncrypted(ctx context.Context, user common.Address) (*service.Credential, error) {
	return r.store.RetrieveWithTokensEncrypted(ctx, user)
}

func (r *credentialRepository) EncryptTokens(cred *service.Credential) (*service.Credential, error) {
	return r.store.EncryptTokens(cred)
}
