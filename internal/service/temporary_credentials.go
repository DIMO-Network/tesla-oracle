package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/shared/pkg/redis"
	"github.com/ethereum/go-ethereum/common"
	rd "github.com/go-redis/redis/v8"
	"github.com/patrickmn/go-cache"
)

const (
	// We want to be closer to follow Redis key naming conventions
	prefix   = "credentials:"
	duration = 5 * time.Minute
)

var (
	ErrNotFound = errors.New("no credentials found for user")
)

type TempCredsStore struct {
	Cache  redis.CacheService
	Cipher cipher.Cipher
}

type Credential struct {
	AccessToken   string    `json:"accessToken"`
	RefreshToken  string    `json:"refreshToken"`
	AccessExpiry  time.Time `json:"accessExpiry"`
	RefreshExpiry time.Time `json:"RefreshExpiry"`
}

// Store stores the given credential for the given user.
func (s *TempCredsStore) Store(ctx context.Context, user common.Address, cred *Credential) error {
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	encCred, err := s.Cipher.Encrypt(string(credJSON))
	if err != nil {
		return fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	cacheKey := prefix + user.Hex()
	s.Cache.Set(ctx, cacheKey, encCred, duration)

	return nil
}

func (s *TempCredsStore) RetrieveAndDelete(ctx context.Context, user common.Address) (*Credential, error) {
	cacheKey := prefix + user.Hex()
	cachedCred := s.Cache.Get(ctx, cacheKey)

	encCred, err := cachedCred.Result()
	if err != nil {
		if errors.Is(err, rd.Nil) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to retrieve cached credentials: %w", err)
	}

	// Don't want a second call to pick this up. Use it or lose it.
	if _, err := s.Cache.Del(ctx, cacheKey).Result(); err != nil {
		return nil, fmt.Errorf("failed to delete cached credentials: %w", err)
	}

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

// Retrieve retrieves the credential for the given user from the cache, decrypts it, delete it and returns it.
func (s *TempCredsStore) Retrieve(ctx context.Context, user common.Address) (*Credential, error) {
	cacheKey := prefix + user.Hex()
	cachedCred := s.Cache.Get(ctx, cacheKey)

	encCred, err := cachedCred.Result()
	if err != nil {
		if errors.Is(err, rd.Nil) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to retrieve cached credentials: %w", err)
	}

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

func (s *TempCredsStore) RetrieveWithTokensEncrypted(ctx context.Context, user common.Address) (*Credential, error) {
	cacheKey := prefix + user.Hex()
	cachedCred := s.Cache.Get(ctx, cacheKey)

	encCred, err := cachedCred.Result()
	if errors.Is(err, rd.Nil) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, fmt.Errorf("failed to retrieve cached credentials: %w", err)
	}

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

func (s *TempCredsStore) EncryptTokens(cred *Credential) (*Credential, error) {
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

// TempCredsLocalStore For local development, we use a different store implementation
type TempCredsLocalStore struct {
	Cache  *cache.Cache
	Cipher cipher.Cipher
}

// Store stores the given credential for the given user.
func (s *TempCredsLocalStore) Store(_ context.Context, user common.Address, cred *Credential) error {
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

func (s *TempCredsLocalStore) Retrieve(_ context.Context, user common.Address) (*Credential, error) {
	cacheKey := prefix + user.Hex()
	cachedCred, ok := s.Cache.Get(cacheKey)
	if !ok {
		return nil, ErrNotFound
	}

	encCred := cachedCred.(string)

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

func (s *TempCredsLocalStore) RetrieveAndDelete(_ context.Context, user common.Address) (*Credential, error) {
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

func (s *TempCredsLocalStore) RetrieveWithTokensEncrypted(_ context.Context, user common.Address) (*Credential, error) {
	cacheKey := prefix + user.Hex()
	cachedCred, ok := s.Cache.Get(cacheKey)
	if !ok {
		return nil, ErrNotFound
	}

	encCred := cachedCred.(string)

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

func (s *TempCredsLocalStore) EncryptTokens(cred *Credential) (*Credential, error) {
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
