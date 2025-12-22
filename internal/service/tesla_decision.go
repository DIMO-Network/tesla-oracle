package service

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/models"
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
				action = ActionStartPolling
				message = MessageReadyToStartDataFlow
				next = &models.NextAction{
					Method:   "POST",
					Endpoint: telemetryStart,
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

// TokenRefreshDecisionTree determines the appropriate action and message based on token refresh error
func TokenRefreshDecisionTree(refreshError error) (*models.StatusDecision, error) {
	if refreshError == nil {
		return nil, fmt.Errorf("no error provided")
	}

	errorMessage := refreshError.Error()
	var action string
	var message string

	// Try to parse as JSON error response
	var teslaError core.TeslaFleetAPIError
	if err := json.Unmarshal([]byte(errorMessage), &teslaError); err == nil {
		// Successfully parsed as JSON, handle Tesla API specific errors
		if teslaError.Error == "login_required" {
			action = ActionLoginRequired

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

		} else {
			// Other Tesla API errors - retry might work
			action = ActionRetryRefresh
			message = fmt.Sprintf("Token refresh failed: %s. Please try again.", teslaError.ErrorDescription)
		}
	} else {
		// Not a JSON error, handle as generic error
		if strings.Contains(strings.ToLower(errorMessage), "expired") ||
			strings.Contains(strings.ToLower(errorMessage), "invalid") ||
			strings.Contains(strings.ToLower(errorMessage), "unauthorized") {
			action = ActionLoginRequired
			message = MessageGenericLoginRequired
		} else {
			// Generic error - might be network or temporary issue
			action = ActionRetryRefresh
			message = fmt.Sprintf("Token refresh failed: %s. Please try again.", errorMessage)
		}
	}

	return &models.StatusDecision{
		Action:  action,
		Message: message,
	}, nil
}
