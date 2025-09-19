package service

import (
	"fmt"
	"testing"

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
			name:            "Non-JSON error with 'expired' keyword",
			refreshError:    fmt.Errorf("token has expired"),
			expectedAction:  ActionLoginRequired,
			expectedMessage: MessageGenericLoginRequired,
		},
		{
			name:            "Non-JSON error with 'invalid' keyword",
			refreshError:    fmt.Errorf("invalid token provided"),
			expectedAction:  ActionLoginRequired,
			expectedMessage: MessageGenericLoginRequired,
		},
		{
			name:            "Non-JSON error with 'unauthorized' keyword",
			refreshError:    fmt.Errorf("unauthorized access"),
			expectedAction:  ActionLoginRequired,
			expectedMessage: MessageGenericLoginRequired,
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
			name:            "Case insensitive expired check",
			refreshError:    fmt.Errorf("Token EXPIRED due to timeout"),
			expectedAction:  ActionLoginRequired,
			expectedMessage: MessageGenericLoginRequired,
		},
		{
			name:            "Case insensitive invalid check",
			refreshError:    fmt.Errorf("INVALID credentials provided"),
			expectedAction:  ActionLoginRequired,
			expectedMessage: MessageGenericLoginRequired,
		},
		{
			name:            "Case insensitive unauthorized check",
			refreshError:    fmt.Errorf("UNAUTHORIZED request"),
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
