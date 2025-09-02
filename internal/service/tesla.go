package service

import (
	"fmt"
	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/rs/zerolog"
	"regexp"
	"strconv"
)

type TeslaService struct {
	settings *config.Settings
	logger   *zerolog.Logger
	Cipher   cipher.Cipher
}

func NewTeslaService(settings *config.Settings, logger *zerolog.Logger, cipher cipher.Cipher) *TeslaService {
	return &TeslaService{
		settings: settings,
		logger:   logger,
		Cipher:   cipher,
	}
}

func DecisionTreeAction(fleetStatus *VehicleFleetStatus, vehicleTokenID int64) (*models.StatusDecision, error) {
	var action string
	var message string
	var next *models.NextAction

	if fleetStatus.VehicleCommandProtocolRequired {
		if fleetStatus.KeyPaired {
			action = models.ActionSetTelemetryConfig
			message = models.MessageReadyToStartDataFlow
			next = &models.NextAction{
				Method:   "POST",
				Endpoint: fmt.Sprintf("/v1/tesla/%d/start", vehicleTokenID),
			}
		} else {
			action = models.ActionOpenTeslaDeeplink
			message = models.MessageVirtualKeyNotPaired
		}
	} else {
		meetsFirmware, err := IsFirmwareFleetTelemetryCapable(fleetStatus.FirmwareVersion)
		if err != nil {
			return nil, fmt.Errorf("unexpected firmware version format %q: %w", fleetStatus.FirmwareVersion, err)
		}
		if !meetsFirmware {
			action = models.ActionUpdateFirmware
			message = models.MessageFirmwareTooOld
		} else {
			if fleetStatus.SafetyScreenStreamingToggleEnabled == nil {
				action = models.ActionStartPolling
				message = models.MessageReadyToStartDataFlow
				next = &models.NextAction{
					Method:   "POST",
					Endpoint: fmt.Sprintf("/v1/tesla/%d/start", vehicleTokenID),
				}
			} else if *fleetStatus.SafetyScreenStreamingToggleEnabled {
				action = models.ActionSetTelemetryConfig
				message = models.MessageReadyToStartDataFlow
				next = &models.NextAction{
					Method:   "POST",
					Endpoint: fmt.Sprintf("/v1/tesla/%d/start", vehicleTokenID),
				}
			} else {
				action = models.ActionPromptToggle
				message = models.MessageStreamingToggleDisabled
			}
		}
	}

	return &models.StatusDecision{
		Action:  action,
		Message: message,
		Next:    next,
	}, nil
}

func IsFleetTelemetryCapable(fs *VehicleFleetStatus) bool {
	// We used to check for the presence of a meaningful value (not ""
	// or "unknown") for fleet_telemetry_version, but this started
	// populating on old cars that are not capable of streaming.
	return fs.VehicleCommandProtocolRequired || !fs.DiscountedDeviceData
}

var teslaFirmwareStart = regexp.MustCompile(`^(\d{4})\.(\d+)`)

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
