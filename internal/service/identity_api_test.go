package service

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestIdentityAPI(t *testing.T, response string) IdentityAPIService {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(server.Close)

	endpoint, err := url.Parse(server.URL)
	require.NoError(t, err)
	logger := zerolog.Nop()
	return NewIdentityAPIService(&logger, &config.Settings{IdentityAPIEndpoint: *endpoint})
}

func TestFetchVehicleByTokenID(t *testing.T) {
	t.Run("returns the vehicle", func(t *testing.T) {
		identity := newTestIdentityAPI(t, `{"data":{"vehicle":{"tokenId":172827,"owner":"0x1234567890AbcdEF1234567890aBcdef12345678","syntheticDevice":{"tokenId":168219}}}}`)

		vehicle, err := identity.FetchVehicleByTokenID(172827)
		require.NoError(t, err)
		assert.Equal(t, "0x1234567890AbcdEF1234567890aBcdef12345678", vehicle.Owner)
		assert.EqualValues(t, 168219, vehicle.SyntheticDevice.TokenID)
	})

	// What identity-api answers, with a 200, for a vehicle that was burned.
	t.Run("reports a vehicle identity-api doesn't have as not found", func(t *testing.T) {
		identity := newTestIdentityAPI(t, `{"errors":[{"message":"No vehicle with token id 172827.","path":["vehicle"],"extensions":{"code":"NOT_FOUND"}}],"data":{"vehicle":null}}`)

		vehicle, err := identity.FetchVehicleByTokenID(172827)
		assert.ErrorIs(t, err, core.ErrVehicleNotFound)
		assert.Nil(t, vehicle)
	})
}
