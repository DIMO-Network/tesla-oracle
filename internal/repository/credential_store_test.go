package repository

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestTempCredsStore(t *testing.T) {
	ctx := context.Background()
	user := common.HexToAddress("0x73b423A85a9206f776aF9b3541A152766226b26F")
	cred := &Credential{
		AccessToken:   "access-token",
		RefreshToken:  "refresh-token",
		AccessExpiry:  time.Now().Add(time.Hour),
		RefreshExpiry: time.Now().Add(24 * time.Hour),
	}

	t.Run("returns the stored credentials to every read", func(t *testing.T) {
		store := NewTempCredsStore(new(cipher.ROT13Cipher))
		require.NoError(t, store.Store(ctx, user, cred))

		for range 2 {
			got, err := store.Retrieve(ctx, user)
			require.NoError(t, err)
			require.Equal(t, cred.AccessToken, got.AccessToken)
			require.Equal(t, cred.RefreshToken, got.RefreshToken)
			require.True(t, cred.AccessExpiry.Equal(got.AccessExpiry))
			require.True(t, cred.RefreshExpiry.Equal(got.RefreshExpiry))
		}
	})

	t.Run("keeps them encrypted in memory", func(t *testing.T) {
		store := NewTempCredsStore(new(cipher.ROT13Cipher))
		require.NoError(t, store.Store(ctx, user, cred))

		for _, item := range store.cache.Items() {
			require.NotContains(t, item.Object.(string), cred.AccessToken)
			require.NotContains(t, item.Object.(string), cred.RefreshToken)
		}
	})

	t.Run("RetrieveAndDelete hands them out once", func(t *testing.T) {
		store := NewTempCredsStore(new(cipher.ROT13Cipher))
		require.NoError(t, store.Store(ctx, user, cred))

		got, err := store.RetrieveAndDelete(ctx, user)
		require.NoError(t, err)
		require.Equal(t, cred.AccessToken, got.AccessToken)

		_, err = store.RetrieveAndDelete(ctx, user)
		require.ErrorIs(t, err, ErrNotFound)
		_, err = store.Retrieve(ctx, user)
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("RetrieveAndDelete hands them out once under concurrent calls", func(t *testing.T) {
		store := NewTempCredsStore(new(cipher.ROT13Cipher))
		require.NoError(t, store.Store(ctx, user, cred))

		var taken atomic.Int32
		var wg sync.WaitGroup
		for range 50 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := store.RetrieveAndDelete(ctx, user); err == nil {
					taken.Add(1)
				}
			}()
		}
		wg.Wait()
		require.EqualValues(t, 1, taken.Load())
	})

	t.Run("RetrieveWithTokensEncrypted encrypts each token", func(t *testing.T) {
		cip := new(cipher.ROT13Cipher)
		store := NewTempCredsStore(cip)
		require.NoError(t, store.Store(ctx, user, cred))

		got, err := store.RetrieveWithTokensEncrypted(ctx, user)
		require.NoError(t, err)
		access, err := cip.Decrypt(got.AccessToken)
		require.NoError(t, err)
		require.Equal(t, cred.AccessToken, access)
		refresh, err := cip.Decrypt(got.RefreshToken)
		require.NoError(t, err)
		require.Equal(t, cred.RefreshToken, refresh)
	})

	t.Run("reports unknown users as not found", func(t *testing.T) {
		store := NewTempCredsStore(new(cipher.ROT13Cipher))

		_, err := store.Retrieve(ctx, user)
		require.ErrorIs(t, err, ErrNotFound)
		_, err = store.RetrieveAndDelete(ctx, user)
		require.ErrorIs(t, err, ErrNotFound)
		_, err = store.RetrieveWithTokensEncrypted(ctx, user)
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("keys credentials by user", func(t *testing.T) {
		store := NewTempCredsStore(new(cipher.ROT13Cipher))
		require.NoError(t, store.Store(ctx, user, cred))

		other := common.HexToAddress(strings.Repeat("11", 20))
		_, err := store.Retrieve(ctx, other)
		require.ErrorIs(t, err, ErrNotFound)
	})
}

func TestTempCredsStoreOnboardingSession(t *testing.T) {
	ctx := context.Background()
	user := common.HexToAddress("0x73b423A85a9206f776aF9b3541A152766226b26F")
	newCred := func(accessToken string) *Credential {
		return &Credential{
			AccessToken:   accessToken,
			RefreshToken:  "refresh-token",
			AccessExpiry:  time.Now().Add(time.Hour),
			RefreshExpiry: time.Now().Add(24 * time.Hour),
			VINs:          []string{"XP7YHCER3SB582506"},
		}
	}

	t.Run("keeps the VINs the Tesla login listed", func(t *testing.T) {
		store := NewTempCredsStore(new(cipher.ROT13Cipher))
		require.NoError(t, store.Store(ctx, user, newCred("access-token")))

		got, err := store.Retrieve(ctx, user)
		require.NoError(t, err)
		require.Equal(t, []string{"XP7YHCER3SB582506"}, got.VINs)
	})

	t.Run("lasts long enough for virtual key setup", func(t *testing.T) {
		require.GreaterOrEqual(t, duration, 30*time.Minute)
	})

	t.Run("DeleteIfUnchanged deletes the credentials that were used", func(t *testing.T) {
		store := NewTempCredsStore(new(cipher.ROT13Cipher))
		used := newCred("access-token")
		require.NoError(t, store.Store(ctx, user, used))

		store.DeleteIfUnchanged(ctx, user, used)

		_, err := store.Retrieve(ctx, user)
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("DeleteIfUnchanged keeps a newer login", func(t *testing.T) {
		store := NewTempCredsStore(new(cipher.ROT13Cipher))
		used := newCred("access-token")
		require.NoError(t, store.Store(ctx, user, used))
		// The user logged in to Tesla again while the old credentials were in use.
		require.NoError(t, store.Store(ctx, user, newCred("newer-access-token")))

		store.DeleteIfUnchanged(ctx, user, used)

		got, err := store.Retrieve(ctx, user)
		require.NoError(t, err)
		require.Equal(t, "newer-access-token", got.AccessToken)
	})
}
