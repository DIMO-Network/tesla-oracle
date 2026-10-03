package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/token-exchange-api/pkg/signercheck"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

var (
	mobileLicense = common.HexToAddress("0x299671D2b32ED62Cc61ce65D8f2b9e4f78486B37")
	memberSigner  = common.HexToAddress("0x71efD5d71a597eB6BEC28DFDB05a49283a3e20c5")
)

type fakeChecker struct {
	result signercheck.Result
	calls  int
}

func (f *fakeChecker) Check(context.Context, common.Address, common.Address) (signercheck.Result, error) {
	f.calls++
	return f.result, nil
}

func serveTelemetry(t *testing.T, mode string, checker *fakeChecker, claims jwt.MapClaims) (int, ErrorRes) {
	t.Helper()
	logger := zerolog.Nop()
	handler, err := SignerCheck(&config.Settings{SignerCheckMode: mode}, checker, &logger)
	require.NoError(t, err)

	app := fiber.New(fiber.Config{ErrorHandler: func(c *fiber.Ctx, err error) error { return ErrorHandler(c, err, &logger) }})
	app.Post("/v1/telemetry/subscribe/:vehicleTokenId",
		func(c *fiber.Ctx) error {
			c.Locals("user", jwt.NewWithClaims(jwt.SigningMethodHS256, claims))
			return c.Next()
		},
		handler,
		func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) },
	)
	resp, err := app.Test(httptest.NewRequest("POST", "/v1/telemetry/subscribe/1", nil), -1)
	require.NoError(t, err)
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var body ErrorRes
	if resp.StatusCode != fiber.StatusOK {
		require.NoError(t, json.Unmarshal(raw, &body))
	}
	return resp.StatusCode, body
}

func TestSignerCheckOnTelemetryRoutes(t *testing.T) {
	memberToken := jwt.MapClaims{"ethereum_address": mobileLicense.Hex(), "signer_address": memberSigner.Hex()}

	status, body := serveTelemetry(t, "enforce", &fakeChecker{result: signercheck.Denied}, memberToken)
	require.Equal(t, fiber.StatusForbidden, status)
	require.Equal(t, signercheck.MessageDenied, body.Message)

	status, _ = serveTelemetry(t, "", &fakeChecker{result: signercheck.Allowed}, memberToken)
	require.Equal(t, fiber.StatusOK, status, "empty mode means enforce, and an enabled signer passes")

	status, _ = serveTelemetry(t, "log", &fakeChecker{result: signercheck.Denied}, memberToken)
	require.Equal(t, fiber.StatusOK, status, "log mode never refuses")

	ownerApp := &fakeChecker{result: signercheck.Denied}
	status, _ = serveTelemetry(t, "enforce", ownerApp, jwt.MapClaims{"ethereum_address": mobileLicense.Hex()})
	require.Equal(t, fiber.StatusOK, status, "the mobile backend's own claimless tokens pass")
	require.Zero(t, ownerApp.calls)

	logger := zerolog.Nop()
	_, err := SignerCheck(&config.Settings{SignerCheckMode: "strict"}, &fakeChecker{}, &logger)
	require.ErrorContains(t, err, "SIGNER_CHECK_MODE")
}
