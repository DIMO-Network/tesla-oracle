package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/ethereum/go-ethereum/common"
	"github.com/patrickmn/go-cache"
)

const (
	prefix = "credentials:"
	// duration is how long credentials from a Tesla OAuth exchange stay
	// available for onboarding. It covers pairing a virtual key in the Tesla app,
	// signing with a passkey and a mint that can take several minutes.
	duration = 30 * time.Minute
)

var (
	ErrNotFound = errors.New("no credentials found for user")
)

// TempCredsStore holds the credentials from a Tesla OAuth exchange, encrypted, in
// this process's memory until onboarding moves them onto the synthetic device.
// Another replica can't see them, so the service runs as a single replica.
type TempCredsStore struct {
	cache  *cache.Cache
	cipher cipher.Cipher
	// takeMu makes RetrieveAndDelete's read and delete one step, so concurrent
	// callers can't both take the same credentials, and a Store that lands
	// meanwhile isn't deleted along with the credentials that were taken.
	takeMu sync.Mutex
}

// NewTempCredsStore returns an empty in-memory credential store.
func NewTempCredsStore(cip cipher.Cipher) *TempCredsStore {
	return &TempCredsStore{
		cache:  cache.New(duration, 2*duration),
		cipher: cip,
	}
}

type Credential struct {
	AccessToken   string    `json:"accessToken"`
	RefreshToken  string    `json:"refreshToken"`
	AccessExpiry  time.Time `json:"accessExpiry"`
	RefreshExpiry time.Time `json:"RefreshExpiry"`
	// VINs are the vehicles Tesla listed for this login. Onboarding only accepts
	// these, so nobody can onboard a VIN their Tesla account can't see.
	VINs []string `json:"vins,omitempty"`
}

// Store stores the given credential for the given user.
func (s *TempCredsStore) Store(_ context.Context, user common.Address, cred *Credential) error {
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	encCred, err := s.cipher.Encrypt(string(credJSON))
	if err != nil {
		return fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	s.takeMu.Lock()
	s.cache.Set(prefix+user.Hex(), encCred, duration)
	s.takeMu.Unlock()

	return nil
}

// Retrieve returns the credential stored for the given user and leaves it in place.
func (s *TempCredsStore) Retrieve(_ context.Context, user common.Address) (*Credential, error) {
	encCred, ok := s.cache.Get(prefix + user.Hex())
	if !ok {
		return nil, ErrNotFound
	}

	return s.decrypt(encCred.(string))
}

// RetrieveAndDelete returns the credential stored for the given user and removes it.
func (s *TempCredsStore) RetrieveAndDelete(_ context.Context, user common.Address) (*Credential, error) {
	cacheKey := prefix + user.Hex()

	// Don't want a second call to pick this up. Use it or lose it.
	s.takeMu.Lock()
	encCred, ok := s.cache.Get(cacheKey)
	s.cache.Delete(cacheKey)
	s.takeMu.Unlock()

	if !ok {
		return nil, ErrNotFound
	}

	return s.decrypt(encCred.(string))
}

// DeleteIfUnchanged removes the credentials stored for the given user if they are
// still the ones in used. A newer Tesla login stored meanwhile stays.
func (s *TempCredsStore) DeleteIfUnchanged(_ context.Context, user common.Address, used *Credential) {
	cacheKey := prefix + user.Hex()

	s.takeMu.Lock()
	defer s.takeMu.Unlock()

	encCred, ok := s.cache.Get(cacheKey)
	if !ok {
		return
	}
	current, err := s.decrypt(encCred.(string))
	if err != nil || current.AccessToken == used.AccessToken {
		s.cache.Delete(cacheKey)
	}
}

// RetrieveWithTokensEncrypted returns the credential stored for the given user
// with each token encrypted, ready to save on a synthetic device.
func (s *TempCredsStore) RetrieveWithTokensEncrypted(ctx context.Context, user common.Address) (*Credential, error) {
	cred, err := s.Retrieve(ctx, user)
	if err != nil {
		return nil, err
	}

	credsWithEncryptedTokens, err := s.EncryptTokens(cred)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	return credsWithEncryptedTokens, nil
}

func (s *TempCredsStore) EncryptTokens(cred *Credential) (*Credential, error) {
	encAccess, err := s.cipher.Encrypt(cred.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt access token: %w", err)
	}

	encRefresh, err := s.cipher.Encrypt(cred.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt refresh token: %w", err)
	}

	return &Credential{
		AccessToken:   encAccess,
		RefreshToken:  encRefresh,
		AccessExpiry:  cred.AccessExpiry,
		RefreshExpiry: cred.RefreshExpiry,
	}, nil
}

func (s *TempCredsStore) decrypt(encCred string) (*Credential, error) {
	if len(encCred) == 0 {
		return nil, fmt.Errorf("no credential found")
	}

	credJSON, err := s.cipher.Decrypt(encCred)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt credentials: %w", err)
	}

	var cred Credential
	if err := json.Unmarshal([]byte(credJSON), &cred); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credentials: %w", err)
	}

	if cred.AccessToken == "" || cred.RefreshToken == "" || cred.AccessExpiry.IsZero() || cred.RefreshExpiry.IsZero() {
		return nil, errors.New("credential was missing a required field")
	}

	return &cred, nil
}
