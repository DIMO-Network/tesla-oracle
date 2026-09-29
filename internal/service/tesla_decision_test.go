package service

import (
	"errors"
	"fmt"
	"testing"

	shttp "github.com/DIMO-Network/shared/pkg/http"
	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenRefreshDecisionTree(t *testing.T) {
	testCases := []struct {
		name            string
		refreshError    error
		expectedAction  string
		expectedMessage string
		expectError     bool
	}{
		{
			name:         "Nil error should return error",
			refreshError: nil,
			expectError:  true,
		},
		{
			name:            "Tesla API refresh token expired error",
			refreshError:    fmt.Errorf(`{"error": "login_required", "error_description": "The refresh_token is expired."}`),
			expectedAction:  ActionLoginRequired,
			expectedMessage: MessageRefreshTokenExpired,
		},
		{
			name:            "Tesla API user revoked consent error",
			refreshError:    fmt.Errorf(`{"error": "login_required", "error_description": "User revoked the consent."}`),
			expectedAction:  ActionLoginRequired,
			expectedMessage: MessageConsentRevoked,
		},
		{
			name:            "Tesla API invalid refresh token error",
			refreshError:    fmt.Errorf(`{"error": "login_required", "error_description": "The refresh_token is invalid. Generate a new refresh_token by forcing user to re-authenticate."}`),
			expectedAction:  ActionLoginRequired,
			expectedMessage: MessageInvalidRefreshToken,
		},
		{
			name:            "Tesla API generic login required error",
			refreshError:    fmt.Errorf(`{"error": "login_required", "error_description": "Some other login required error."}`),
			expectedAction:  ActionLoginRequired,
			expectedMessage: MessageGenericLoginRequired,
		},
		{
			name:            "Tesla API non-login error (should retry)",
			refreshError:    fmt.Errorf(`{"error": "server_error", "error_description": "Internal server error occurred."}`),
			expectedAction:  ActionRetryRefresh,
			expectedMessage: "Token refresh failed: Internal server error occurred.. Please try again.",
		},
		{
			// A transport or TLS error that happens to say "expired" is not a Tesla
			// verdict on the user's login.
			name:            "Non-JSON error with 'expired' keyword (should retry)",
			refreshError:    fmt.Errorf("x509: certificate has expired or is not yet valid"),
			expectedAction:  ActionRetryRefresh,
			expectedMessage: "Token refresh failed: x509: certificate has expired or is not yet valid. Please try again.",
		},
		{
			name:            "Non-JSON error with 'invalid' keyword (should retry)",
			refreshError:    fmt.Errorf("invalid character '<' looking for beginning of value"),
			expectedAction:  ActionRetryRefresh,
			expectedMessage: "Token refresh failed: invalid character '<' looking for beginning of value. Please try again.",
		},
		{
			name:            "Non-JSON generic network error (should retry)",
			refreshError:    fmt.Errorf("network connection failed"),
			expectedAction:  ActionRetryRefresh,
			expectedMessage: "Token refresh failed: network connection failed. Please try again.",
		},
		{
			name:            "Non-JSON timeout error (should retry)",
			refreshError:    fmt.Errorf("request timeout"),
			expectedAction:  ActionRetryRefresh,
			expectedMessage: "Token refresh failed: request timeout. Please try again.",
		},
		{
			name:            "Stored refresh token past its expiry",
			refreshError:    core.ErrTokenExpired,
			expectedAction:  ActionLoginRequired,
			expectedMessage: MessageRefreshTokenExpired,
		},
		{
			// KMS says "InvalidCiphertextException" when a key is rotated or revoked.
			// That is our outage, not the user's: polling must survive it.
			name:            "Credential decryption failure (should retry)",
			refreshError:    fmt.Errorf("%w: InvalidCiphertextException: unauthorized", core.ErrCredentialDecryption),
			expectedAction:  ActionRetryRefresh,
			expectedMessage: "Token refresh failed: failed to decrypt credentials: InvalidCiphertextException: unauthorized. Please try again.",
		},
		{
			name:            "Tesla 401 without a JSON body",
			refreshError:    fmt.Errorf("failed to perform request: %w", shttp.BuildResponseError(401, errors.New("received non success status code 401 for url https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token with body: <html>Unauthorized</html>"))),
			expectedAction:  ActionLoginRequired,
			expectedMessage: MessageGenericLoginRequired,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// when
			decision, err := TokenRefreshDecisionTree(tc.refreshError)

			// then
			if tc.expectError {
				require.Error(t, err)
				assert.Nil(t, decision)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, decision)

			assert.Equal(t, tc.expectedAction, decision.Action)
			assert.Equal(t, tc.expectedMessage, decision.Message)

			// Next field is not set in the current implementation
			// The action field provides the necessary information
			assert.Nil(t, decision.Next)
		})
	}
}

func TestTokenRefreshDecisionTreeErrorDescriptionMatching(t *testing.T) {
	testCases := []struct {
		name             string
		errorDescription string
		expectedMessage  string
	}{
		{
			name:             "Exact match: The refresh_token is expired.",
			errorDescription: "The refresh_token is expired.",
			expectedMessage:  MessageRefreshTokenExpired,
		},
		{
			name:             "Partial match: refresh_token is expired",
			errorDescription: "Something bad happened: The refresh_token is expired. Please try again.",
			expectedMessage:  MessageRefreshTokenExpired,
		},
		{
			name:             "Exact match: User revoked the consent.",
			errorDescription: "User revoked the consent.",
			expectedMessage:  MessageConsentRevoked,
		},
		{
			name:             "Partial match: revoked the consent",
			errorDescription: "The user has revoked the consent for this application.",
			expectedMessage:  MessageConsentRevoked,
		},
		{
			name:             "Exact match: refresh_token is invalid",
			errorDescription: "The refresh_token is invalid. Generate a new refresh_token by forcing user to re-authenticate.",
			expectedMessage:  MessageInvalidRefreshToken,
		},
		{
			name:             "Partial match: refresh_token is invalid",
			errorDescription: "Error: The provided refresh_token is invalid and cannot be used.",
			expectedMessage:  MessageInvalidRefreshToken,
		},
		{
			name:             "No match should use generic message",
			errorDescription: "Some completely different error message.",
			expectedMessage:  MessageGenericLoginRequired,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// given
			teslaErrorJSON := fmt.Sprintf(`{"error": "login_required", "error_description": "%s"}`, tc.errorDescription)
			refreshError := fmt.Errorf("%s", teslaErrorJSON)

			// when
			decision, err := TokenRefreshDecisionTree(refreshError)

			// then
			require.NoError(t, err)
			require.NotNil(t, decision)
			assert.Equal(t, ActionLoginRequired, decision.Action)
			assert.Equal(t, tc.expectedMessage, decision.Message)
		})
	}
}

// TestTokenRefreshDecisionTreeProdErrors feeds the errors exactly as RefreshToken
// returns them in prod: shttp wraps Tesla's JSON body inside a status-code message,
// and RefreshToken wraps that again. Before, none of these parsed as JSON, and
// "user session flushed" or a revoked consent came back as retry_refresh, so the
// app never asked the user to log in again and polling retried the dead token forever.
func TestTokenRefreshDecisionTreeProdErrors(t *testing.T) {
	prodBody := func(description string) string {
		return `received non success status code 401 for url https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token with body: {"error":"login_required","error_description":"` + description + `"}` + "\n"
	}

	testCases := []struct {
		name            string
		description     string
		expectedMessage string
	}{
		{name: "user session flushed", description: "user session flushed", expectedMessage: MessageGenericLoginRequired},
		{name: "revoked consent", description: "The user has revoked the consent", expectedMessage: MessageConsentRevoked},
		{name: "refresh token expired", description: "The refresh_token is expired.", expectedMessage: MessageRefreshTokenExpired},
	}

	for _, tc := range testCases {
		for _, wrap := range []struct {
			name string
			err  error
		}{
			{name: "typed response error", err: fmt.Errorf("failed to perform request: %w", shttp.BuildResponseError(401, errors.New(prodBody(tc.description))))},
			{name: "message only", err: fmt.Errorf("failed to perform request: %s", prodBody(tc.description))},
		} {
			t.Run(tc.name+"/"+wrap.name, func(t *testing.T) {
				decision, err := TokenRefreshDecisionTree(wrap.err)
				require.NoError(t, err)
				assert.Equal(t, ActionLoginRequired, decision.Action)
				assert.Equal(t, tc.expectedMessage, decision.Message)
			})
		}
	}
}
