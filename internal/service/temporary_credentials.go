package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/ethereum/go-ethereum/common"
	"github.com/patrickmn/go-cache"
)

const (
	prefix   = "credentials_"
	duration = 5 * time.Minute
)

var (
	ErrNotFound = errors.New("no credentials found for user")
)

type Store struct {
	Cache  *cache.Cache
	Cipher cipher.Cipher
}

type Credential struct {
	AccessToken   string    `json:"accessToken"`
	RefreshToken  string    `json:"refreshToken"`
	AccessExpiry  time.Time `json:"accessExpiry"`
	RefreshExpiry time.Time `json:"RefreshExpiry"`
}

// Store stores the given credential for the given user.
func (s *Store) Store(_ context.Context, user common.Address, cred *Credential) error {
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	encCred, err := s.Cipher.Encrypt(string(credJSON))
	if err != nil {
		return fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	cacheKey := prefix + user.Hex()
	s.Cache.Set(cacheKey, encCred, duration)

	return nil
}

func (s *Store) Retrieve(_ context.Context, user common.Address) (*Credential, error) {
	cacheKey := prefix + user.Hex()
	cachedCred, ok := s.Cache.Get(cacheKey)
	if !ok {
		return nil, ErrNotFound
	}

	encCred := cachedCred.(string)

	// Don't want a second call to pick this up. Use it or lose it.
	s.Cache.Delete(cacheKey)

	if len(encCred) == 0 {
		return nil, fmt.Errorf("no credential found")
	}

	credJSON, err := s.Cipher.Decrypt(encCred)
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

func (s *Store) RetrieveWithTokensEncrypted(_ context.Context, user common.Address) (*Credential, error) {
	cacheKey := prefix + user.Hex()
	cachedCred, ok := s.Cache.Get(cacheKey)
	if !ok {
		return nil, ErrNotFound
	}

	encCred := cachedCred.(string)

	// Don't want a second call to pick this up. Use it or lose it.
	s.Cache.Delete(cacheKey)

	if len(encCred) == 0 {
		return nil, fmt.Errorf("no credential found")
	}

	credJSON, err := s.Cipher.Decrypt(encCred)
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

	credsWithEncryptedTokens, err := s.EncryptTokens(&cred)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	return credsWithEncryptedTokens, nil
}

func (s *Store) EncryptTokens(cred *Credential) (*Credential, error) {
	encAccess, err := s.Cipher.Encrypt(cred.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt access token: %w", err)
	}

	encRefresh, err := s.Cipher.Encrypt(cred.RefreshToken)
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
