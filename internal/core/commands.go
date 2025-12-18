package core

import (
	"fmt"
	"strings"
)

// Command status constants for Tesla device commands
const (
	CommandStatusPending   = "pending"   // Command has been submitted and is waiting to be processed
	CommandStatusCompleted = "completed" // Command has been successfully executed
	CommandStatusFailed    = "failed"    // Command execution failed
)

// Supported Tesla commands
const (
	CommandFrunkOpen   = "frunk/open"
	CommandTrunkOpen   = "trunk/open"
	CommandDoorsLock   = "doors/lock"
	CommandDoorsUnlock = "doors/unlock"
	CommandChargeStart = "charge/start"
	CommandChargeStop  = "charge/stop"
	CommandWakeup      = "wakeup"
)

const (
	ChargeLimit                 = "charge/limit"
	CommandTelemetrySubscribe   = "telemetry/subscribe"
	CommandTelemetryUnsubscribe = "telemetry/unsubscribe"
	CommandTelemetryStart       = "telemetry/start"
)

// ValidateCommand validates the command against supported commands
func ValidateCommand(command string) error {
	if command == "" {
		return fmt.Errorf("%w: command field is required", ErrBadRequest)
	}

	// Validate command against supported commands
	if !IsCommandSupported(command) {
		return fmt.Errorf("%w: command '%s' is not supported. Supported commands: %s",
			ErrUnsupportedCommand, command, GetSupportedCommandsList())
	}

	return nil
}

// IsCommandSupported checks if the command is in the list of supported commands
func IsCommandSupported(command string) bool {
	supportedCommands := map[string]bool{
		CommandFrunkOpen:            true,
		CommandTrunkOpen:            true,
		CommandDoorsLock:            true,
		CommandDoorsUnlock:          true,
		CommandChargeStart:          true,
		CommandChargeStop:           true,
		CommandWakeup:               true,
		CommandTelemetrySubscribe:   true,
		CommandTelemetryUnsubscribe: true,
		CommandTelemetryStart:       true,
	}

	return supportedCommands[command]
}

// GetSupportedCommandsList returns a comma-separated list of supported commands for error messages
func GetSupportedCommandsList() string {
	commands := []string{
		CommandFrunkOpen,
		CommandTrunkOpen,
		CommandDoorsLock,
		CommandDoorsUnlock,
		CommandChargeStart,
		CommandChargeStop,
		CommandWakeup,
		CommandTelemetrySubscribe,
		CommandTelemetryUnsubscribe,
		CommandTelemetryStart,
	}

	return strings.Join(commands, ", ")
}

// GetEventTypeForCommand returns the CloudEvent type for each Tesla command
// Based on legacy implementation: different commands have different event types
// so the consumer knows which Tesla API endpoint to call
func GetEventTypeForCommand(command string) string {
	prefix := "zone.dimo.task.tesla"
	commandEventTypes := map[string]string{
		CommandFrunkOpen:            fmt.Sprintf("%s.frunk.open", prefix),
		CommandTrunkOpen:            fmt.Sprintf("%s.trunk.open", prefix),
		CommandDoorsLock:            fmt.Sprintf("%s.doors.lock", prefix),
		CommandDoorsUnlock:          fmt.Sprintf("%s.doors.unlock", prefix),
		CommandChargeStart:          fmt.Sprintf("%s.charge.start", prefix),
		CommandChargeStop:           fmt.Sprintf("%s.charge.stop", prefix),
		CommandWakeup:               fmt.Sprintf("%s.wakeup", prefix),
		CommandTelemetrySubscribe:   fmt.Sprintf("%s.telemetry.subscribe", prefix),
		CommandTelemetryUnsubscribe: fmt.Sprintf("%s.telemetry.unsubscribe", prefix),
		CommandTelemetryStart:       fmt.Sprintf("%s.telemetry.start", prefix),
	}

	if eventType, exists := commandEventTypes[command]; exists {
		return eventType
	}

	// Fallback to generic command type if command not found
	return "com.tesla.vehicle.command.generic"
}
