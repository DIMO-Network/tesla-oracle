package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	shttp "github.com/DIMO-Network/shared/pkg/http"
	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/gofiber/fiber/v2"
)

const (
	ActionSetTelemetryConfig  = "set_telemetry_config"
	ActionOpenTeslaDeeplink   = "open_tesla_deeplink"
	ActionUpdateFirmware      = "update_firmware"
	ActionStartPolling        = "start_polling"
	ActionPromptToggle        = "prompt_toggle"
	ActionDummy               = "do_nothing"
	ActionTelemetryConfigured = "telemetry_configured"
)

// Token refresh error actions
const (
	ActionRetryRefresh  = "retry_refresh"
	ActionLoginRequired = "login_required"
	ActionMissingScopes = "missing_scopes"
)

const (
	MessageReadyToStartDataFlow    = "Vehicle ready to start data flow. Call start data flow endpoint"
	MessageVirtualKeyNotPaired     = "Virtual key not paired. Open Tesla app deeplink for pairing."
	MessageFirmwareTooOld          = "Firmware too old. Please update to 2025.20 or higher."
	MessageStreamingToggleDisabled = "Streaming toggle disabled. Prompt user to enable it."
	MessageTelemetryConfigured     = "Telemetry configuration already set, no need to call /start endpoint"
)

// Token refresh error messages
const (
	MessageRefreshTokenExpired  = "Refresh token has expired. User must re-authenticate through Tesla."
	MessageConsentRevoked       = "User has revoked consent. User should add it back."
	MessageInvalidRefreshToken  = "Refresh token is invalid. User must re-authenticate through Tesla."
	MessageGenericLoginRequired = "Authentication required. User must log in again through Tesla."
)

// DecisionTreeAction determines the appropriate action and message based on vehicle fleet status
func DecisionTreeAction(fleetStatus *core.VehicleFleetStatus, vehicleTokenID int64) (*models.StatusDecision, error) {
	var action string
	var message string
	var next *models.NextAction

	telemetryStart := fmt.Sprintf("/v1/telemetry/%d/start", vehicleTokenID)

	if fleetStatus.VehicleCommandProtocolRequired {
		if fleetStatus.KeyPaired {
			action = ActionSetTelemetryConfig
			message = MessageReadyToStartDataFlow
			next = &models.NextAction{
				Method:   "POST",
				Endpoint: telemetryStart,
			}
		} else {
			action = ActionOpenTeslaDeeplink
			message = MessageVirtualKeyNotPaired
		}
	} else {
		meetsFirmware, err := IsFirmwareFleetTelemetryCapable(fleetStatus.FirmwareVersion)
		if err != nil {
			return nil, fmt.Errorf("unexpected firmware version format %q: %w", fleetStatus.FirmwareVersion, err)
		}
		if !meetsFirmware {
			action = ActionUpdateFirmware
			message = MessageFirmwareTooOld
		} else {
			if fleetStatus.SafetyScreenStreamingToggleEnabled == nil {
				if fleetStatus.DiscountedDeviceData {
					action = ActionStartPolling
					message = MessageReadyToStartDataFlow
					next = &models.NextAction{
						Method:   "POST",
						Endpoint: telemetryStart,
					}
				} else {
					// There are some cars that have vehicle_command_protocol_required as false,
					// but are virtual key-capable and stream-capable.
					if fleetStatus.KeyPaired {
						action = ActionSetTelemetryConfig
						message = MessageReadyToStartDataFlow
						next = &models.NextAction{
							Method:   "POST",
							Endpoint: telemetryStart,
						}
					} else {
						action = ActionOpenTeslaDeeplink
						message = MessageVirtualKeyNotPaired
					}
				}
			} else if *fleetStatus.SafetyScreenStreamingToggleEnabled {
				action = ActionSetTelemetryConfig
				message = MessageReadyToStartDataFlow
				next = &models.NextAction{
					Method:   "POST",
					Endpoint: telemetryStart,
				}
			} else {
				action = ActionPromptToggle
				message = MessageStreamingToggleDisabled
			}
		}
	}

	return &models.StatusDecision{
		Action:  action,
		Message: message,
		Next:    next,
	}, nil
}

// IsFleetTelemetryCapable checks if a vehicle is capable of fleet telemetry
func IsFleetTelemetryCapable(fs *core.VehicleFleetStatus) bool {
	// We used to check for the presence of a meaningful value (not ""
	// or "unknown") for fleet_telemetry_version, but this started
	// populating on old cars that are not capable of streaming.
	return fs.VehicleCommandProtocolRequired || !fs.DiscountedDeviceData
}

var teslaFirmwareStart = regexp.MustCompile(`^(\d{4})\.(\d+)`)

// IsFirmwareFleetTelemetryCapable checks if the firmware version supports fleet telemetry
func IsFirmwareFleetTelemetryCapable(v string) (bool, error) {
	m := teslaFirmwareStart.FindStringSubmatch(v)
	if len(m) != 3 {
		return false, fmt.Errorf("unexpected firmware version format %q", v)
	}

	year, err := strconv.Atoi(m[1])
	if err != nil {
		return false, fmt.Errorf("couldn't parse year %q", m[1])
	}

	week, err := strconv.Atoi(m[2])
	if err != nil {
		return false, fmt.Errorf("couldn't parse week %q", m[2])
	}

	return year > 2025 || (year == 2025 && week >= 20), nil
}

// TokenRefreshDecisionTree determines the appropriate action and message based on token refresh error.
//
// Only Tesla itself can say the user's login is gone: a login_required from its
// OAuth endpoint, a 401 from it, or our stored refresh token being past its expiry.
// Everything else (network, TLS, KMS decryption, malformed responses) is ours or
// transient, and gets retry_refresh so polling survives it.
func TokenRefreshDecisionTree(refreshError error) (*models.StatusDecision, error) {
	if refreshError == nil {
		return nil, fmt.Errorf("no error provided")
	}

	if errors.Is(refreshError, core.ErrTokenExpired) {
		return &models.StatusDecision{Action: ActionLoginRequired, Message: MessageRefreshTokenExpired}, nil
	}

	if !errors.Is(refreshError, core.ErrCredentialDecryption) {
		if teslaError, ok := parseTeslaOAuthError(refreshError); ok {
			if teslaError.Error != "login_required" {
				// Other Tesla API errors - retry might work
				return &models.StatusDecision{
					Action:  ActionRetryRefresh,
					Message: fmt.Sprintf("Token refresh failed: %s. Please try again.", teslaError.ErrorDescription),
				}, nil
			}

			var message string
			switch {
			case strings.Contains(teslaError.ErrorDescription, "refresh_token is expired"):
				message = MessageRefreshTokenExpired
			case strings.Contains(teslaError.ErrorDescription, "revoked the consent"):
				message = MessageConsentRevoked
			case strings.Contains(teslaError.ErrorDescription, "refresh_token is invalid"):
				message = MessageInvalidRefreshToken
			default:
				message = MessageGenericLoginRequired
			}
			return &models.StatusDecision{Action: ActionLoginRequired, Message: message}, nil
		}

		var respErr shttp.ResponseError
		if errors.As(refreshError, &respErr) && respErr.StatusCode == fiber.StatusUnauthorized {
			return &models.StatusDecision{Action: ActionLoginRequired, Message: MessageGenericLoginRequired}, nil
		}
	}

	// Generic error - might be network or temporary issue
	return &models.StatusDecision{
		Action:  ActionRetryRefresh,
		Message: fmt.Sprintf("Token refresh failed: %s. Please try again.", refreshError.Error()),
	}, nil
}

// teslaBodyMarker precedes the response body in the errors shttp builds for
// non-2xx responses.
const teslaBodyMarker = "with body:"

// parseTeslaOAuthError finds Tesla's OAuth error JSON in a refresh error. The error
// is either the bare JSON body, or shttp's "received non success status code ...
// with body: {...}" message, possibly wrapped by RefreshToken.
func parseTeslaOAuthError(err error) (core.TeslaFleetAPIError, bool) {
	message := err.Error()
	var respErr shttp.ResponseError
	if errors.As(err, &respErr) {
		message = respErr.Error()
	}

	candidates := []string{message}
	if i := strings.LastIndex(message, teslaBodyMarker); i >= 0 {
		candidates = append(candidates, message[i+len(teslaBodyMarker):])
	}

	for _, candidate := range candidates {
		var teslaError core.TeslaFleetAPIError
		if json.Unmarshal([]byte(strings.TrimSpace(candidate)), &teslaError) == nil && teslaError.Error != "" {
			return teslaError, true
		}
	}

	return core.TeslaFleetAPIError{}, false
}
