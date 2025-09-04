package service

import (
	"fmt"
	"regexp"
	"strconv"

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

const (
	MessageReadyToStartDataFlow    = "Vehicle ready to start data flow. Call start data flow endpoint"
	MessageVirtualKeyNotPaired     = "Virtual key not paired. Open Tesla app deeplink for pairing."
	MessageFirmwareTooOld          = "Firmware too old. Please update to 2025.20 or higher."
	MessageStreamingToggleDisabled = "Streaming toggle disabled. Prompt user to enable it."
	MessageTelemetryConfigured     = "Telemetry configuration already set, no need to call /start endpoint"
)

// DecisionTreeAction determines the appropriate action and message based on vehicle fleet status and telemetry status
func DecisionTreeAction(fleetStatus *VehicleFleetStatus, telemetryStatus *VehicleTelemetryStatus, vehicleTokenID int64) (*models.StatusDecision, error) {
	var action string
	var message string
	var next *models.NextAction

	// Check if telemetry is already configured first
	if telemetryStatus != nil && telemetryStatus.Configured {
		return &models.StatusDecision{
			Action:  ActionTelemetryConfigured,
			Message: MessageTelemetryConfigured,
			Next:    nil,
		}, nil
	}

	telemetryStart := fmt.Sprintf("/v1/tesla/telemetry/%d/start", vehicleTokenID)

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
func IsFleetTelemetryCapable(fs *VehicleFleetStatus) bool {
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
