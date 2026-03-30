package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestErrorHandlerLogsChecksummedUserFromJWT(t *testing.T) {
	var logBuf bytes.Buffer
	logger := zerolog.New(&logBuf)

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return ErrorHandler(c, err, &logger)
		},
	})

	app.Use(func(c *fiber.Ctx) error {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"ethereum_address": "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
		})
		c.Locals("user", token)
		return c.Next()
	})

	app.Get("/v1/test", func(c *fiber.Ctx) error {
		return errors.New("boom")
	})

	req := httptest.NewRequest("GET", "/v1/test", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(logBuf.Bytes(), &entry))
	require.Equal(t, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", entry["user"])
	require.Equal(t, "GET", entry["httpMethod"])
	require.Equal(t, "/v1/test", entry["httpPath"])
}

func TestErrorHandlerOmitsUserWhenClaimMissing(t *testing.T) {
	var logBuf bytes.Buffer
	logger := zerolog.New(&logBuf)

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return ErrorHandler(c, err, &logger)
		},
	})

	app.Use(func(c *fiber.Ctx) error {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "user-123",
		})
		c.Locals("user", token)
		return c.Next()
	})

	app.Get("/v1/test", func(c *fiber.Ctx) error {
		return errors.New("boom")
	})

	req := httptest.NewRequest("GET", "/v1/test", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(logBuf.Bytes(), &entry))
	_, ok := entry["user"]
	require.False(t, ok)
}

func TestErrorHandlerOmitsUserWhenNoJWT(t *testing.T) {
	var logBuf bytes.Buffer
	logger := zerolog.New(&logBuf)

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return ErrorHandler(c, err, &logger)
		},
	})

	app.Get("/v1/test", func(c *fiber.Ctx) error {
		return errors.New("boom")
	})

	req := httptest.NewRequest("GET", "/v1/test", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(logBuf.Bytes(), &entry))
	_, ok := entry["user"]
	require.False(t, ok)
}

func TestErrorHandlerOmitsUserWhenClaimInvalid(t *testing.T) {
	var logBuf bytes.Buffer
	logger := zerolog.New(&logBuf)

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return ErrorHandler(c, err, &logger)
		},
	})

	app.Use(func(c *fiber.Ctx) error {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"ethereum_address": "not-an-address",
		})
		c.Locals("user", token)
		return c.Next()
	})

	app.Get("/v1/test", func(c *fiber.Ctx) error {
		return errors.New("boom")
	})

	req := httptest.NewRequest("GET", "/v1/test", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(logBuf.Bytes(), &entry))
	_, ok := entry["user"]
	require.False(t, ok)
}
