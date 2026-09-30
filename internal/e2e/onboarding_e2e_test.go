// Package e2e runs tesla-oracle the way prod wires it (bootstrap.InitializeServices
// and app.App, with a real Postgres, River and the onboarding worker) against local
// fakes of everything outside the process, and drives Tesla onboarding over HTTP.
package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DIMO-Network/tesla-oracle/internal/app"
	"github.com/DIMO-Network/tesla-oracle/internal/bootstrap"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/consumer"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/test"
	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	work "github.com/DIMO-Network/tesla-oracle/internal/workers"
	"github.com/IBM/sarama"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	signer "github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/gofiber/fiber/v2"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

const (
	ddID          = "tesla_model-y_2025"
	scratchEnvVar = "E2E_CONTRACT_OUT" // where to write the /status contract table, if set
)

type harness struct {
	t        *testing.T
	ctx      context.Context
	settings config.Settings
	services *bootstrap.Services
	app      *fiber.App
	db       *sql.DB
	jwt      *jwtIssuer
	tesla    *fakeTesla
	identity *fakeIdentity
	chain    *fakeChain
}

func newHarness(t *testing.T) *harness {
	ctx := context.Background()
	pdb, container, settings := test.StartContainerDatabase(ctx, t, "../../migrations")
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	migrator, err := rivermigrate.New(riverdatabasesql.New(pdb.DBS().Writer.DB), &rivermigrate.Config{Schema: "tesla_oracle"})
	require.NoError(t, err)
	_, err = migrator.Migrate(ctx, rivermigrate.DirectionUp, nil)
	require.NoError(t, err)

	scopes := []string{"openid", "offline_access", "vehicle_device_data", "vehicle_cmds", "vehicle_charging_cmds"}
	h := &harness{
		t:        t,
		ctx:      ctx,
		db:       pdb.DBS().Writer.DB,
		jwt:      newJWTIssuer(t),
		tesla:    newFakeTesla(t, scopes),
		identity: newFakeIdentity(t),
	}
	registryAddr := common.HexToAddress("0x00000000000000000000000000000000000000e1")
	h.chain = newFakeChain(t, registryAddr, 137)
	dd := newFakeDeviceDefinitions(t, ddID)

	devKey, devAA := newKey(t)
	authKey, authClient := newKey(t)
	certPEM, keyPEM := selfSignedPEM(t)

	settings.Environment = "test" // not dev/prod: bootstrap picks the ROT13 test cipher
	settings.JwtKeySetURL = h.jwt.server.URL
	settings.TokenExchangeJWTKeySetURL = h.jwt.server.URL
	settings.ChainID = 137
	settings.RPCURL = mustURL(t, h.chain.server.URL)
	settings.BundlerURL = mustURL(t, h.chain.server.URL)
	settings.RegistryAddress = registryAddr
	settings.VehicleNftAddress = common.HexToAddress("0x00000000000000000000000000000000000000e2")
	settings.SyntheticNftAddress = common.HexToAddress("0x00000000000000000000000000000000000000e3")
	settings.DeveloperAAWalletAddress = devAA
	settings.DeveloperPK = hex.EncodeToString(crypto.FromECDSA(devKey))
	settings.SDWalletsSeed = "cabaabd8c7c7d27347349e48fb11319bc6656cb6cc1bdc717e94dae8db7e6bc2"
	settings.ConnectionTokenID = "1"
	settings.IdentityAPIEndpoint = mustURL(t, h.identity.server.URL+"/query")
	settings.DeviceDefinitionsAPIEndpoint = mustURL(t, dd.URL)
	settings.DimoAuthURL = mustURL(t, dd.URL)
	settings.DimoAuthClientID = authClient
	settings.DimoAuthDomain = mustURL(t, "https://e2e.example")
	settings.DimoAuthPrivateKey = hex.EncodeToString(crypto.FromECDSA(authKey))
	settings.TeslaClientID = "tesla-client"
	settings.TeslaClientSecret = "tesla-secret"
	settings.TeslaAuthURL = mustURL(t, h.tesla.server.URL+"/oauth2/v3/authorize")
	settings.TeslaRedirectURL = mustURL(t, "https://e2e.example/callback")
	settings.TeslaTokenURL = mustURL(t, h.tesla.server.URL+"/oauth2/v3/token")
	settings.TeslaFleetURL = mustURL(t, h.tesla.server.URL)
	settings.PartnersTeslaFleetURL = h.tesla.server.URL
	settings.TeslaVirtualKeyURL = mustURL(t, "https://tesla.com/_ak/e2e.example")
	settings.TeslaRequiredScopes = "vehicle_device_data,vehicle_cmds"
	settings.TeslaTelemetryHostName = "telemetry.e2e.example"
	settings.TeslaTelemetryPort = 443
	settings.TeslaTelemetryTopic = "topic.device.integration.ingest.tesla_V"
	settings.TeslaTelemetryGroup = "e2e"
	settings.TeslaConnectionAddr = "0x00000000000000000000000000000000000000e4"
	settings.TeslaDISClientTLSCert = certPEM
	settings.TeslaDISClientTLSKey = keyPEM
	settings.TeslaDISCACert = certPEM
	settings.TeslaDISHost = "https://127.0.0.1:9"
	settings.TelemetryMappingRefreshInterval = "10m"
	settings.MobileAppDevLicense = common.HexToAddress("0x299671D2b32ED62Cc61ce65D8f2b9e4f78486B37")
	h.settings = settings

	logger := zerolog.New(zerolog.NewTestWriter(t)).Level(zerolog.WarnLevel)
	if os.Getenv("E2E_LOG") != "" {
		logger = logger.Level(zerolog.DebugLevel)
	}
	services, err := bootstrap.InitializeServices(ctx, &logger, &h.settings)
	require.NoError(t, err)
	t.Cleanup(services.Cleanup)
	h.services = services

	riverCtx, stopRiver := context.WithCancel(context.Background())
	require.NoError(t, services.RiverClient.Start(riverCtx))
	t.Cleanup(func() {
		stopRiver()
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = services.RiverClient.Stop(stopCtx)
	})

	h.app = app.App(&h.settings, &logger, services.TeslaService, services.VehicleOnboardService, services.RiverClient, services.Repositories.Command)
	return h
}

// call sends one request through the real Fiber app (middleware included).
func (h *harness) call(method, path, jwtToken string, body any) (int, []byte) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(h.t, err)
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if jwtToken != "" {
		req.Header.Set("Authorization", "Bearer "+jwtToken)
	}
	resp, err := h.app.Test(req, 60_000)
	require.NoError(h.t, err)
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	require.NoError(h.t, err)
	return resp.StatusCode, out
}

// with returns the harness bound to a subtest, so a failed check stops only that
// subtest.
func (h *harness) with(t *testing.T) *harness {
	c := *h
	c.t = t
	return &c
}

func (h *harness) exec(query string, args ...any) {
	h.t.Helper()
	_, err := h.db.ExecContext(h.ctx, query, args...)
	require.NoError(h.t, err)
}

func (h *harness) count(query string, args ...any) int {
	h.t.Helper()
	var n int
	require.NoError(h.t, h.db.QueryRowContext(h.ctx, query, args...).Scan(&n))
	return n
}

// oauth runs the web's Tesla login step: POST /v1/vehicles with a fresh code.
func (h *harness) oauth(userJWT, account string) []string {
	h.t.Helper()
	code, body := h.call(http.MethodPost, "/v1/vehicles", userJWT, map[string]string{
		"authorizationCode": h.tesla.authCode(account),
		"redirectUri":       "https://e2e.example/callback",
	})
	require.Equal(h.t, http.StatusOK, code, string(body))
	var res struct {
		Vehicles []struct {
			VIN string `json:"vin"`
		} `json:"vehicles"`
	}
	require.NoError(h.t, json.Unmarshal(body, &res))
	vins := make([]string, 0, len(res.Vehicles))
	for _, v := range res.Vehicles {
		vins = append(vins, v.VIN)
	}
	return vins
}

type vinStatus struct {
	Vin     string `json:"vin"`
	Status  string `json:"status"`
	Details string `json:"details"`
}

func (h *harness) verify(userJWT, vin string, vehicleTokenID int64) (int, []vinStatus, string) {
	h.t.Helper()
	entry := map[string]any{"vin": vin}
	if vehicleTokenID != 0 {
		entry["vehicleTokenId"] = vehicleTokenID
	}
	code, body := h.call(http.MethodPost, "/v1/vehicle/verify", userJWT, map[string]any{"vins": []any{entry}})
	var res struct {
		Statuses []vinStatus `json:"statuses"`
	}
	_ = json.Unmarshal(body, &res)
	return code, res.Statuses, string(body)
}

// mintAndSubmit fetches the typed data, signs it as the owner, and submits it.
func (h *harness) mintAndSubmit(userJWT string, ownerKey signerKey, vin string) {
	h.t.Helper()
	code, body := h.call(http.MethodGet, "/v1/vehicle/mint?vins="+vin, userJWT, nil)
	require.Equal(h.t, http.StatusOK, code, string(body))
	var mint struct {
		VinMintingData []struct {
			Vin       string            `json:"vin"`
			TypedData *signer.TypedData `json:"typedData"`
		} `json:"vinMintingData"`
	}
	require.NoError(h.t, json.Unmarshal(body, &mint))
	require.Len(h.t, mint.VinMintingData, 1)
	td := mint.VinMintingData[0].TypedData
	require.NotNil(h.t, td)

	hash, _, err := signer.TypedDataAndHash(*td)
	require.NoError(h.t, err)
	sig, err := crypto.Sign(hash, ownerKey.key)
	require.NoError(h.t, err)
	sig[64] += 27

	code, body = h.call(http.MethodPost, "/v1/vehicle/mint", userJWT, map[string]any{"vinMintingData": []any{map[string]any{
		"vin":       vin,
		"typedData": td,
		"signature": "0x" + hex.EncodeToString(sig),
	}}})
	require.Equal(h.t, http.StatusOK, code, string(body))
	require.Contains(h.t, string(body), `"Pending"`)
}

// waitMinted polls GET /v1/vehicle/mint/status like the web does.
func (h *harness) waitMinted(userJWT, vin string) {
	h.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		code, body := h.call(http.MethodGet, "/v1/vehicle/mint/status?vins="+vin, userJWT, nil)
		require.Equal(h.t, http.StatusOK, code, string(body))
		if strings.Contains(string(body), `"status":"Success"`) {
			return
		}
		require.NotContains(h.t, string(body), `"status":"Failure"`, "mint failed")
		time.Sleep(200 * time.Millisecond)
	}
	h.t.Fatalf("VIN %s never reached minted", vin)
}

// waitOnboardJob waits for the VIN's onboard job to finish and returns how it ended.
func (h *harness) waitOnboardJob(vin string) (state string, attempt, maxAttempts int) {
	h.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := h.db.QueryRowContext(h.ctx, `SELECT state, attempt, max_attempts FROM tesla_oracle.river_job
			WHERE kind='onboard' AND args->>'vin'=$1 AND finalized_at IS NOT NULL`, vin).Scan(&state, &attempt, &maxAttempts)
		if err == nil {
			return state, attempt, maxAttempts
		}
		require.ErrorIs(h.t, err, sql.ErrNoRows)
		require.True(h.t, time.Now().Before(deadline), "onboard job for %s never finished", vin)
		time.Sleep(100 * time.Millisecond)
	}
}

func (h *harness) finalize(userJWT, vin string) (int, string) {
	h.t.Helper()
	code, body := h.call(http.MethodPost, "/v1/vehicle/finalize", userJWT, map[string]any{"vins": []string{vin}})
	return code, string(body)
}

func (h *harness) hasTempCreds(wallet common.Address) bool {
	_, err := h.services.Repositories.Credential.Retrieve(h.ctx, wallet)
	if errors.Is(err, repository.ErrNotFound) {
		return false
	}
	require.NoError(h.t, err)
	return true
}

type signerKey struct {
	key  *ecdsa.PrivateKey
	addr common.Address
}

func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}

// insertDevice writes a synthetic_devices row with ROT13-encrypted tokens, as the
// test cipher stores them.
func (h *harness) insertDevice(address common.Address, vin string, vehicleID int64, sdID *int64, walletChild *int64, accessToken, refreshToken string, accessExpiry time.Time, status string) {
	h.t.Helper()
	var at, rt any
	if accessToken != "" {
		at, rt = rot13(accessToken), rot13(refreshToken)
	}
	h.exec(`INSERT INTO tesla_oracle.synthetic_devices
		(address, vin, vehicle_token_id, token_id, wallet_child_number, access_token, access_expires_at, refresh_token, refresh_expires_at, subscription_status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		address.Bytes(), vin, vehicleID, sdID, walletChild, at, accessExpiry, rt, time.Now().AddDate(0, 3, 0), status)
}

func ptr[T any](v T) *T { return &v }

func TestTeslaOnboardingE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("needs Docker for Postgres")
	}
	h := newHarness(t)

	keyA, walletA := newKey(t)
	_, walletB := newKey(t)
	ownerA := signerKey{key: keyA, addr: walletA}
	jwtA := h.jwt.token(t, walletA)
	jwtB := h.jwt.token(t, walletB)
	jwtDev := h.jwt.token(t, h.settings.MobileAppDevLicense)

	const (
		vin1 = "7SAYGDEE1SA000001" // new onboarding
		vin3 = "7SAYGDEE1SA000003" // reconnect with command history
		vin4 = "7SAYGDEE1SA000004" // stuck at 53
		vin5 = "7SAYGDEE1SA000005" // finalize fails once
		vin6 = "7SAYGDEE1SA000006" // lost mint receipt
		vin7 = "7SAYGDEE1SA000007" // reconnect, verify before identity-api shows the new SD
		vin8 = "7SAYGDEE1SA000081" // new onboarding, verify before identity-api shows the mint
		vinB = "5YJSA1E26GF000009" // attacker's own car
	)
	// Seven VINs: Tesla's list pages at 5, so vin6 and vin8 only arrive on page 2.
	h.tesla.addAccount("alice", vin1, vin3, vin4, vin5, vin7, vin6, vin8)
	h.tesla.addAccount("mallory", vinB)

	t.Run("1 new onboarding, identity lag", func(t *testing.T) {
		h := h.with(t)
		vins := h.oauth(jwtA, "alice")
		require.Contains(t, vins, vin6, "the 6th VIN is on page 2 of Tesla's list")
		require.True(t, h.hasTempCreds(walletA))

		code, body := h.call(http.MethodPost, "/v1/disconnected", jwtA, map[string]any{"vins": []string{vin1}})
		require.Equal(t, http.StatusOK, code, string(body))
		require.Contains(t, string(body), `"new":["`+vin1+`"]`)

		code, statuses, raw := h.verify(jwtA, vin1, 0)
		require.Equal(t, http.StatusOK, code, raw)
		require.Equal(t, "Ready to mint Vehicle and Synthetic Device", statuses[0].Details)

		// identity-api indexes the new vehicle 3s after it's minted.
		h.chain.expectMint(mintOutcome{vehicleID: 500001, sdID: 600001, owner: walletA, onMined: func() {
			h.identity.setVehicle(500001, idVehicle{owner: walletA, ddID: ddID, sdTokenID: 600001, visibleAt: time.Now().Add(3 * time.Second)})
		}})
		h.mintAndSubmit(jwtA, ownerA, vin1)
		h.waitMinted(jwtA, vin1)
		state, attempt, maxAttempts := h.waitOnboardJob(vin1)
		require.Equal(t, "completed", state)
		require.Equal(t, 1, attempt)
		require.Equal(t, 1, maxAttempts, "a mint job must never be retried")

		start := time.Now()
		code, raw = h.finalize(jwtA, vin1)
		took := time.Since(start)
		require.Equal(t, http.StatusOK, code, raw)
		require.Contains(t, raw, `"vehicleTokenId":500001`)
		require.Contains(t, raw, `"syntheticTokenId":600001`)
		require.Greater(t, took, 500*time.Millisecond, "finalize should have waited for identity-api")
		t.Logf("finalize waited %s for identity-api to index the mint", took.Round(100*time.Millisecond))

		require.Equal(t, 1, h.count(`SELECT count(*) FROM tesla_oracle.synthetic_devices WHERE vin=$1 AND vehicle_token_id=500001 AND token_id=600001
			AND access_token IS NOT NULL AND access_token<>'' AND refresh_token IS NOT NULL AND wallet_child_number IS NOT NULL AND subscription_status='pending'`, vin1))
		require.Equal(t, 0, h.count(`SELECT count(*) FROM tesla_oracle.onboarding WHERE vin=$1`, vin1))
		require.False(t, h.hasTempCreds(walletA), "the Tesla login is used up by finalize")
	})

	t.Run("2 attacker without Tesla access to the VIN", func(t *testing.T) {
		h := h.with(t)
		// Alice logs in again, so vin5 has a verified record an attacker could target.
		h.oauth(jwtA, "alice")
		require.Equal(t, 1, h.count(`SELECT count(*) FROM tesla_oracle.onboarding WHERE vin=$1 AND onboarding_status=23`, vin5))

		h.oauth(jwtB, "mallory") // Mallory's Tesla account lists only vinB
		h.exec(`DELETE FROM tesla_oracle.onboarding WHERE vin=$1`, vinB)
		snapshot := func() string {
			var s string
			require.NoError(t, h.db.QueryRowContext(h.ctx, `SELECT coalesce((SELECT json_agg(o ORDER BY vin)::text FROM tesla_oracle.onboarding o), '') || coalesce((SELECT json_agg(d ORDER BY address)::text FROM tesla_oracle.synthetic_devices d), '')`).Scan(&s))
			return s
		}
		before := snapshot()
		sendsBefore := h.chain.sendCount()

		code, _, raw := h.verify(jwtB, vin5, 0)
		require.Equal(t, http.StatusForbidden, code, raw)
		code, body := h.call(http.MethodGet, "/v1/vehicle/mint?vins="+vin5, jwtB, nil)
		require.Equal(t, http.StatusForbidden, code, string(body))
		code, body = h.call(http.MethodPost, "/v1/vehicle/mint", jwtB, map[string]any{"vinMintingData": []any{map[string]any{"vin": vin5, "signature": "0x01"}}})
		require.Equal(t, http.StatusForbidden, code, string(body))
		code, raw = h.finalize(jwtB, vin5)
		require.Equal(t, http.StatusForbidden, code, raw)

		// A VIN nobody ever onboarded: no record gets created.
		const neverSeen = "7SAYGDEE1SA0000ZZ"
		code, body = h.call(http.MethodPost, "/v1/vehicle/mint", jwtB, map[string]any{"vinMintingData": []any{map[string]any{"vin": neverSeen, "signature": "0x01"}}})
		require.Equal(t, http.StatusForbidden, code, string(body))
		require.Equal(t, 0, h.count(`SELECT count(*) FROM tesla_oracle.onboarding WHERE vin=$1`, neverSeen))

		// Mallory's own VIN, with its record gone: submit no longer creates one.
		code, body = h.call(http.MethodPost, "/v1/vehicle/mint", jwtB, map[string]any{"vinMintingData": []any{map[string]any{"vin": vinB, "signature": "0x01"}}})
		require.Equal(t, http.StatusBadRequest, code, string(body))
		require.Equal(t, 0, h.count(`SELECT count(*) FROM tesla_oracle.onboarding WHERE vin=$1`, vinB))

		require.Equal(t, before, snapshot(), "attacker calls must not change any row")
		require.Equal(t, sendsBefore, h.chain.sendCount(), "no mint was sent")
		require.Equal(t, 0, h.count(`SELECT count(*) FROM tesla_oracle.river_job WHERE kind='onboard' AND args->>'vin'=$1`, vin5))
	})

	t.Run("3 reconnect with command history", func(t *testing.T) {
		h := h.with(t)
		oldAddr := common.HexToAddress("0x0000000000000000000000000000000000003003")
		h.insertDevice(oldAddr, vin3, 500003, nil, nil, "", "", time.Time{}, "active")
		h.exec(`INSERT INTO tesla_oracle.device_command_requests (id, vehicle_token_id, command, status) VALUES ('cmd-3', 500003, 'doors/lock', 'completed')`)
		h.identity.setVehicle(500003, idVehicle{owner: walletA, ddID: ddID})

		h.oauth(jwtA, "alice")
		code, body := h.call(http.MethodPost, "/v1/disconnected", jwtA, map[string]any{"vins": []string{vin3}})
		require.Equal(t, http.StatusOK, code, string(body))
		require.Contains(t, string(body), `"vehicleTokenId":500003`)

		code, statuses, raw := h.verify(jwtA, vin3, 500003)
		require.Equal(t, http.StatusOK, code, raw)
		require.Equal(t, "Ready to mint Synthetic Device", statuses[0].Details)

		h.chain.expectMint(mintOutcome{vehicleID: 500003, sdID: 600003, owner: walletA, onMined: func() {
			h.identity.setVehicle(500003, idVehicle{owner: walletA, ddID: ddID, sdTokenID: 600003})
		}})
		h.mintAndSubmit(jwtA, ownerA, vin3)
		h.waitMinted(jwtA, vin3)

		code, raw = h.finalize(jwtA, vin3)
		require.Equal(t, http.StatusOK, code, raw)

		var addr []byte
		var tokenID sql.NullInt64
		var status string
		var accessToken sql.NullString
		require.NoError(t, h.db.QueryRowContext(h.ctx, `SELECT address, token_id, subscription_status, access_token FROM tesla_oracle.synthetic_devices WHERE vehicle_token_id=500003`).Scan(&addr, &tokenID, &status, &accessToken))
		require.NotEqual(t, oldAddr.Bytes(), addr, "the row moved to the new SD's address")
		require.Equal(t, int64(600003), tokenID.Int64)
		require.Equal(t, "active", status, "a reconnection keeps its subscription status")
		require.True(t, accessToken.Valid && accessToken.String != "")
		require.Equal(t, 1, h.count(`SELECT count(*) FROM tesla_oracle.synthetic_devices WHERE vehicle_token_id=500003`))
		require.Equal(t, 1, h.count(`SELECT count(*) FROM tesla_oracle.device_command_requests WHERE id='cmd-3' AND vehicle_token_id=500003`), "command history survives")
	})

	t.Run("4 stuck at 53 resumes without a new mint", func(t *testing.T) {
		h := h.with(t)
		h.exec(`UPDATE tesla_oracle.onboarding SET vehicle_token_id=500004, synthetic_token_id=600004, onboarding_status=53, wallet_index=424242, device_definition_id=$2 WHERE vin=$1`, vin4, ddID)
		require.Equal(t, 1, h.count(`SELECT count(*) FROM tesla_oracle.onboarding WHERE vin=$1 AND onboarding_status=53`, vin4))
		h.identity.setVehicle(500004, idVehicle{owner: walletA, ddID: ddID, sdTokenID: 600004})

		h.oauth(jwtA, "alice")
		sends := h.chain.sendCount()
		code, statuses, raw := h.verify(jwtA, vin4, 0)
		require.Equal(t, http.StatusOK, code, raw)
		require.Equal(t, service.DetailsReadyToFinalize, statuses[0].Details)

		code, raw = h.finalize(jwtA, vin4)
		require.Equal(t, http.StatusOK, code, raw)
		require.Contains(t, raw, `"syntheticTokenId":600004`)
		require.Equal(t, sends, h.chain.sendCount(), "no new mint")
		require.Equal(t, 1, h.count(`SELECT count(*) FROM tesla_oracle.synthetic_devices WHERE vehicle_token_id=500004 AND token_id=600004 AND wallet_child_number=424242`))
		require.Equal(t, 0, h.count(`SELECT count(*) FROM tesla_oracle.onboarding WHERE vin=$1`, vin4))
	})

	t.Run("5 failed finalize keeps the Tesla login for a retry", func(t *testing.T) {
		h := h.with(t)
		h.oauth(jwtA, "alice")
		code, _, raw := h.verify(jwtA, vin5, 0)
		require.Equal(t, http.StatusOK, code, raw)
		h.chain.expectMint(mintOutcome{vehicleID: 500005, sdID: 600005, owner: walletA, onMined: func() {
			h.identity.setVehicle(500005, idVehicle{owner: walletA, ddID: ddID, sdTokenID: 600005})
		}})
		h.mintAndSubmit(jwtA, ownerA, vin5)
		h.waitMinted(jwtA, vin5)

		// Make the synthetic_devices write fail once: another row already holds the
		// new SD's address (the primary key).
		var walletIndex int64
		require.NoError(t, h.db.QueryRowContext(h.ctx, `SELECT wallet_index FROM tesla_oracle.onboarding WHERE vin=$1`, vin5).Scan(&walletIndex))
		sdAddr, err := h.services.WalletService.GetAddress(h.ctx, uint32(walletIndex))
		require.NoError(t, err)
		h.insertDevice(sdAddr, "7SAYGDEE1SA0000XX", 599999, nil, nil, "", "", time.Time{}, "pending")

		code, raw = h.finalize(jwtA, vin5)
		require.NotEqual(t, http.StatusOK, code, raw)
		require.True(t, h.hasTempCreds(walletA), "a failed finalize must not use up the Tesla login")
		require.Equal(t, 1, h.count(`SELECT count(*) FROM tesla_oracle.onboarding WHERE vin=$1 AND onboarding_status=53`, vin5), "the record stays for the retry")
		require.Equal(t, 0, h.count(`SELECT count(*) FROM tesla_oracle.synthetic_devices WHERE vehicle_token_id=500005`), "nothing half-written")

		h.exec(`DELETE FROM tesla_oracle.synthetic_devices WHERE vehicle_token_id=599999`)
		code, raw = h.finalize(jwtA, vin5)
		require.Equal(t, http.StatusOK, code, raw)
		require.False(t, h.hasTempCreds(walletA))
		require.Equal(t, 1, h.count(`SELECT count(*) FROM tesla_oracle.synthetic_devices WHERE vehicle_token_id=500005 AND token_id=600005`))
	})

	t.Run("6 lost mint receipt parks the record, one attempt", func(t *testing.T) {
		h := h.with(t)
		h.oauth(jwtA, "alice")
		code, _, raw := h.verify(jwtA, vin6, 0)
		require.Equal(t, http.StatusOK, code, raw)
		sends := h.chain.sendCount()
		h.chain.expectMint(mintOutcome{lostReceipt: true})
		h.mintAndSubmit(jwtA, ownerA, vin6)

		h.waitOnboardJob(vin6)
		time.Sleep(2 * time.Second) // room for a retry, if one were coming
		state, attempt, maxAttempts := h.waitOnboardJob(vin6)
		require.Equal(t, "discarded", state)
		require.Equal(t, 1, attempt)
		require.Equal(t, 1, maxAttempts)
		require.Equal(t, sends+1, h.chain.sendCount(), "exactly one user operation sent")
		require.Equal(t, 1, h.count(`SELECT count(*) FROM tesla_oracle.onboarding WHERE vin=$1 AND onboarding_status=50 AND wallet_index IS NOT NULL AND synthetic_token_id IS NULL`, vin6))
	})

	t.Run("7 admin wake-up route is gone", func(t *testing.T) {
		h := h.with(t)
		// A connected car with a live Tesla token: the old route would have woken it.
		h.tesla.mu.Lock()
		access := h.tesla.accessToken("alice")
		h.tesla.mu.Unlock()
		h.insertDevice(common.HexToAddress("0x0000000000000000000000000000000000007007"), "7SAYGDEE1SA000077", 500007, ptr(int64(600007)), ptr(int64(7007)), access, "rt-7", time.Now().Add(time.Hour), "active")
		code, body := h.call(http.MethodPost, "/v1/admin/500007/wakeup", jwtB, nil)
		require.Equal(t, http.StatusNotFound, code, string(body))
		require.Contains(t, string(body), "Cannot POST /v1/admin/500007/wakeup", "no route, not a handler error")
		require.Zero(t, h.tesla.wakeCount(), "nothing woke the car")
	})

	t.Run("8 login_required from Tesla", func(t *testing.T) {
		h := h.with(t)
		expired := time.Now().Add(-time.Hour)
		h.tesla.flushRefresh("rt-flushed-8")
		h.insertDevice(common.HexToAddress("0x0000000000000000000000000000000000008008"), "7SAYGDEE1SA000008", 500008, ptr(int64(600008)), ptr(int64(8008)), "at-8", "rt-flushed-8", expired, "active")
		code, body := h.call(http.MethodGet, "/v1/500008/status", jwtDev, nil)
		require.Equal(t, http.StatusOK, code, string(body))
		require.Contains(t, string(body), `"action":"login_required"`)

		// The legacy poller stops for the same answer.
		h.tesla.flushRefresh("rt-flushed-18")
		h.insertDevice(common.HexToAddress("0x0000000000000000000000000000000000008018"), "5YJSA1E26GF000018", 500018, ptr(int64(600018)), ptr(int64(8018)), "at-18", "rt-flushed-18", expired, "active")
		_, err := h.services.RiverClient.Insert(h.ctx, work.LegacyTeslaPollArgs{VehicleTokenID: 500018, VIN: "5YJSA1E26GF000018"}, nil)
		require.NoError(t, err)
		deadline := time.Now().Add(30 * time.Second)
		for h.count(`SELECT count(*) FROM tesla_oracle.synthetic_devices WHERE vehicle_token_id=500018 AND subscription_status='pending'`) == 0 {
			require.True(t, time.Now().Before(deadline), "legacy poller never marked the device pending")
			time.Sleep(200 * time.Millisecond)
		}

		// A KMS/decrypt failure is transient. (The ROT13 cipher bootstrap uses outside
		// dev/prod can't fail, so this is checked on the decision itself.)
		d, err := service.TokenRefreshDecisionTree(fmt.Errorf("%w: operation error KMS: Decrypt, InvalidCiphertextException", core.ErrCredentialDecryption))
		require.NoError(t, err)
		require.Equal(t, service.ActionRetryRefresh, d.Action)
	})

	t.Run("9 vehicle burn cascades command history", func(t *testing.T) {
		h := h.with(t)
		h.insertDevice(common.HexToAddress("0x0000000000000000000000000000000000009009"), "7SAYGDEE1SA000009", 500009, ptr(int64(600009)), ptr(int64(9009)), "at-9", "rt-9", time.Now().Add(time.Hour), "active")
		h.exec(`INSERT INTO tesla_oracle.device_command_requests (id, vehicle_token_id, command, status) VALUES ('cmd-9a', 500009, 'doors/lock', 'completed'), ('cmd-9b', 500009, 'charge/start', 'failed')`)

		event := map[string]any{
			"id": "burn-9", "source": "e2e", "producer": "e2e", "specversion": "1.0", "subject": "e2e",
			"time": time.Now().UTC(), "type": "zone.dimo.contract.event",
			"data": map[string]any{
				"eventName":      "Transfer",
				"eventSignature": "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
				"contract":       h.settings.VehicleNftAddress.Hex(),
				"arguments":      map[string]any{"from": walletA.Hex(), "to": common.Address{}.Hex(), "tokenId": 500009},
			},
		}
		value, err := json.Marshal(event)
		require.NoError(t, err)

		logger := zerolog.New(zerolog.NewTestWriter(t)).Level(zerolog.WarnLevel)
		proc := consumer.New(*h.services.DB, h.services.TeslaService, "topic.contract.event", h.settings.VehicleNftAddress, &logger)
		sess := &fakeSession{ctx: h.ctx}
		claim := newFakeClaim(&sarama.ConsumerMessage{Topic: "topic.contract.event", Value: value})
		require.NoError(t, proc.ConsumeClaim(sess, claim))

		require.Equal(t, 1, sess.marked(), "the event is committed")
		require.Equal(t, 0, h.count(`SELECT count(*) FROM tesla_oracle.synthetic_devices WHERE vehicle_token_id=500009`))
		require.Equal(t, 0, h.count(`SELECT count(*) FROM tesla_oracle.device_command_requests WHERE vehicle_token_id=500009`))
	})

	t.Run("10 status contract per car type", func(t *testing.T) {
		h := h.with(t)
		type fixture struct {
			name   string
			fleet  fleetFixture
			action string
		}
		fixtures := []fixture{
			{"a VCP required, key paired", fleetFixture{VCP: true, KeyPaired: true, Firmware: "2025.32.3"}, "set_telemetry_config"},
			{"b VCP required, key not paired", fleetFixture{VCP: true, Firmware: "2025.32.3"}, "open_tesla_deeplink"},
			{"c no VCP, discounted (legacy polling)", fleetFixture{Discounted: true, Firmware: "2025.32.3"}, "telemetry_configured"},
			{"d no VCP, firmware 2025.20+, streaming toggle on", fleetFixture{Firmware: "2025.26.7", Toggle: ptr(true)}, "set_telemetry_config"},
			{"e no VCP, streaming toggle off", fleetFixture{Firmware: "2025.26.7", Toggle: ptr(false)}, "prompt_toggle"},
			{"f no VCP, firmware too old", fleetFixture{Firmware: "2024.44.25"}, "update_firmware"},
			{"g VCP required, key paired, telemetry configured", fleetFixture{VCP: true, KeyPaired: true, Firmware: "2025.32.3", Configured: true}, "telemetry_configured"},
		}
		type row struct {
			Fixture string          `json:"fixture"`
			Fleet   map[string]any  `json:"fleetStatus"`
			Status  int             `json:"httpStatus"`
			Body    json.RawMessage `json:"body"`
		}
		table := make([]row, 0, len(fixtures))
		for i, fx := range fixtures {
			vin := fmt.Sprintf("7SAYGDEE1SA1000%02d", i)
			vehicleID := int64(510000 + i)
			h.tesla.setFleet(vin, fx.fleet)
			// A valid, unexpired Tesla token for the device.
			h.tesla.mu.Lock()
			access := h.tesla.accessToken("device")
			h.tesla.mu.Unlock()
			h.insertDevice(common.BigToAddress(big.NewInt(0x10000+int64(i))), vin, vehicleID, ptr(int64(610000+i)), ptr(int64(10000+i)), access, "rt-dev", time.Now().Add(time.Hour), "active")

			code, body := h.call(http.MethodGet, fmt.Sprintf("/v1/%d/status", vehicleID), jwtDev, nil)
			var decision struct {
				Action string `json:"action"`
			}
			_ = json.Unmarshal(body, &decision)
			require.Equal(t, http.StatusOK, code, "%s: %s", fx.name, body)
			require.Equal(t, fx.action, decision.Action, "%s: %s", fx.name, body)

			fleet := map[string]any{
				"key_paired": fx.fleet.KeyPaired, "vehicle_command_protocol_required": fx.fleet.VCP,
				"discounted_device_data": fx.fleet.Discounted, "firmware_version": fx.fleet.Firmware,
				"fleet_telemetry_config_set": fx.fleet.Configured,
			}
			if fx.fleet.Toggle != nil {
				fleet["safety_screen_streaming_toggle_enabled"] = *fx.fleet.Toggle
			}
			table = append(table, row{Fixture: fx.name, Fleet: fleet, Status: code, Body: bytes.TrimSpace(body)})
		}
		if out := os.Getenv(scratchEnvVar); out != "" {
			b, err := json.MarshalIndent(table, "", "  ")
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(out, b, 0o600))
			t.Logf("wrote %s", out)
		}
	})

	// The user reloads or presses Continue right after the mint: verify used to ask
	// identity-api once and fail with "already onboarded".
	t.Run("11 verify right after a mint waits for identity-api", func(t *testing.T) {
		h := h.with(t)
		h.oauth(jwtA, "alice")
		code, statuses, raw := h.verify(jwtA, vin8, 0)
		require.Equal(t, http.StatusOK, code, raw)
		require.Equal(t, "Ready to mint Vehicle and Synthetic Device", statuses[0].Details)

		h.chain.expectMint(mintOutcome{vehicleID: 500081, sdID: 600081, owner: walletA, onMined: func() {
			h.identity.setVehicle(500081, idVehicle{owner: walletA, ddID: ddID, sdTokenID: 600081, visibleAt: time.Now().Add(3 * time.Second)})
		}})
		h.mintAndSubmit(jwtA, ownerA, vin8)
		h.waitMinted(jwtA, vin8)
		sends := h.chain.sendCount()

		start := time.Now()
		code, statuses, raw = h.verify(jwtA, vin8, 0)
		took := time.Since(start)
		require.Equal(t, http.StatusOK, code, raw)
		require.Equal(t, service.DetailsReadyToFinalize, statuses[0].Details)
		require.Greater(t, took, 500*time.Millisecond, "verify should have waited for identity-api")

		code, raw = h.finalize(jwtA, vin8)
		require.Equal(t, http.StatusOK, code, raw)
		require.Contains(t, raw, `"syntheticTokenId":600081`)
		require.Equal(t, sends, h.chain.sendCount(), "no second mint")
	})

	// Worse for a reconnection: before identity-api shows the new SD, the vehicle looks
	// disconnected, and verify used to re-arm the minted record for a second SD mint.
	t.Run("12 reconnect verify right after the SD mint keeps the minted record", func(t *testing.T) {
		h := h.with(t)
		h.insertDevice(common.HexToAddress("0x0000000000000000000000000000000000007070"), vin7, 500070, nil, nil, "", "", time.Time{}, "active")
		h.identity.setVehicle(500070, idVehicle{owner: walletA, ddID: ddID})

		h.oauth(jwtA, "alice")
		code, statuses, raw := h.verify(jwtA, vin7, 500070)
		require.Equal(t, http.StatusOK, code, raw)
		require.Equal(t, "Ready to mint Synthetic Device", statuses[0].Details)

		h.chain.expectMint(mintOutcome{vehicleID: 500070, sdID: 600070, owner: walletA, onMined: func() {
			h.identity.setVehicle(500070, idVehicle{owner: walletA, ddID: ddID, sdTokenID: 600070, sdVisibleAt: time.Now().Add(3 * time.Second)})
		}})
		h.mintAndSubmit(jwtA, ownerA, vin7)
		h.waitMinted(jwtA, vin7)
		sends := h.chain.sendCount()

		code, statuses, raw = h.verify(jwtA, vin7, 500070)
		require.Equal(t, http.StatusOK, code, raw)
		require.Equal(t, service.DetailsReadyToFinalize, statuses[0].Details)
		require.Equal(t, 1, h.count(`SELECT count(*) FROM tesla_oracle.onboarding WHERE vin=$1 AND onboarding_status=53 AND synthetic_token_id=600070`, vin7),
			"the minted record must not be re-armed for a second mint")

		code, raw = h.finalize(jwtA, vin7)
		require.Equal(t, http.StatusOK, code, raw)
		require.Equal(t, sends, h.chain.sendCount(), "no second mint")
		require.Equal(t, 1, h.count(`SELECT count(*) FROM tesla_oracle.synthetic_devices WHERE vehicle_token_id=500070 AND token_id=600070 AND subscription_status='active'`))
	})

	t.Run("13 unsubscribing one of a car's connections keeps the others streaming", func(t *testing.T) {
		h := h.with(t)
		const vin13 = "7SAYGDEE1SA000013"
		addrA := common.HexToAddress("0x0000000000000000000000000000000000001301")
		addrB := common.HexToAddress("0x0000000000000000000000000000000000001302")
		// Two wallets' vehicle NFTs, each connected to the same Tesla.
		h.insertDevice(addrA, vin13, 501301, ptr(int64(601301)), ptr(int64(1301)), "at-13a", "rt-13a", time.Now().Add(time.Hour), "active")
		h.insertDevice(addrB, vin13, 501302, ptr(int64(601302)), ptr(int64(1302)), "at-13b", "rt-13b", time.Now().Add(time.Hour), "active")
		h.identity.setVehicle(501301, idVehicle{owner: walletA, ddID: ddID, sdTokenID: 601301, sdAddress: addrA})
		h.identity.setVehicle(501302, idVehicle{owner: walletB, ddID: ddID, sdTokenID: 601302, sdAddress: addrB})
		status := func(vehicleID int) string {
			var s string
			require.NoError(t, h.db.QueryRowContext(h.ctx, `SELECT subscription_status FROM tesla_oracle.synthetic_devices WHERE vehicle_token_id=$1`, vehicleID).Scan(&s))
			return s
		}

		// Wallet A's subscription ends (the backend's Stripe webhook or expired-trial cleanup).
		code, raw := h.call(http.MethodPost, "/v1/telemetry/unsubscribe/501301", jwtDev, nil)
		require.Equal(t, http.StatusOK, code, string(raw))
		require.Equal(t, 0, h.tesla.configDeleteCount(vin13), "B is still active: Tesla's config for the car must stay")
		require.Equal(t, "inactive", status(501301))
		require.Equal(t, "active", status(501302))

		// Then B's ends too: nobody is left, so the config goes.
		code, raw = h.call(http.MethodPost, "/v1/telemetry/unsubscribe/501302", jwtDev, nil)
		require.Equal(t, http.StatusOK, code, string(raw))
		require.Equal(t, 1, h.tesla.configDeleteCount(vin13))
		require.Equal(t, "inactive", status(501302))
	})
}

// --- a minimal sarama session and claim to drive the contract-event consumer ---

type fakeSession struct {
	ctx  context.Context
	mu   sync.Mutex
	mark int
}

func (s *fakeSession) Claims() map[string][]int32               { return nil }
func (s *fakeSession) MemberID() string                         { return "e2e" }
func (s *fakeSession) GenerationID() int32                      { return 1 }
func (s *fakeSession) MarkOffset(string, int32, int64, string)  {}
func (s *fakeSession) Commit()                                  {}
func (s *fakeSession) ResetOffset(string, int32, int64, string) {}
func (s *fakeSession) Context() context.Context                 { return s.ctx }
func (s *fakeSession) MarkMessage(*sarama.ConsumerMessage, string) {
	s.mu.Lock()
	s.mark++
	s.mu.Unlock()
}
func (s *fakeSession) marked() int { s.mu.Lock(); defer s.mu.Unlock(); return s.mark }

type fakeClaim struct{ ch chan *sarama.ConsumerMessage }

func newFakeClaim(msgs ...*sarama.ConsumerMessage) *fakeClaim {
	ch := make(chan *sarama.ConsumerMessage, len(msgs))
	for _, m := range msgs {
		ch <- m
	}
	close(ch)
	return &fakeClaim{ch: ch}
}

func (c *fakeClaim) Topic() string                            { return "topic.contract.event" }
func (c *fakeClaim) Partition() int32                         { return 0 }
func (c *fakeClaim) InitialOffset() int64                     { return 0 }
func (c *fakeClaim) HighWaterMarkOffset() int64               { return 1 }
func (c *fakeClaim) Messages() <-chan *sarama.ConsumerMessage { return c.ch }
