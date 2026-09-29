package workers

import (
	"errors"
	"fmt"
	"testing"

	shttp "github.com/DIMO-Network/shared/pkg/http"
	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/stretchr/testify/assert"
)

// TestShouldDisablePolling pins which refresh failures end a car's poll chain.
// Only a dead Tesla login may; our own outages (KMS, network) must not, or one
// incident would stop polling for every legacy car until each owner reauthenticates.
func TestShouldDisablePolling(t *testing.T) {
	teslaLoginRequired := func(description string) error {
		return fmt.Errorf("failed to perform request: %w", shttp.BuildResponseError(401, errors.New(
			`received non success status code 401 for url https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token with body: {"error":"login_required","error_description":"`+description+`"}`)))
	}

	testCases := []struct {
		name    string
		err     error
		disable bool
	}{
		{name: "stored refresh token expired", err: core.ErrTokenExpired, disable: true},
		{name: "Tesla flushed the user session", err: teslaLoginRequired("user session flushed"), disable: true},
		{name: "user revoked consent", err: teslaLoginRequired("The user has revoked the consent"), disable: true},
		{name: "KMS rejected the ciphertext", err: fmt.Errorf("%w: InvalidCiphertextException", core.ErrCredentialDecryption), disable: false},
		{name: "TLS certificate expired", err: errors.New("x509: certificate has expired or is not yet valid"), disable: false},
		{name: "Tesla server error", err: fmt.Errorf("failed to perform request: %w", shttp.BuildResponseError(500, errors.New("received non success status code 500 for url x with body: oops"))), disable: false},
	}

	w := &LegacyTeslaPollWorker{}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.disable, w.shouldDisablePolling(tc.err))
		})
	}
}
