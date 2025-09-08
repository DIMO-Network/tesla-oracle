package service

import (
	"fmt"
	"strings"
)

// Supported Tesla commands
const (
	CommandFrunkOpen   = "frunk/open"
	CommandTrunkOpen   = "trunk/open"
	CommandDoorsLock   = "doors/lock"
	CommandDoorsUnlock = "doors/unlock"
	CommandChargeStart = "charge/start"
	CommandChargeStop  = "charge/stop"
)

// validateCommand validates the command against supported commands
func validateCommand(command string) error {
	if command == "" {
		return fmt.Errorf("%w: command field is required", ErrBadRequest)
	}

	// Validate command against supported commands
	if !isCommandSupported(command) {
		return fmt.Errorf("%w: command '%s' is not supported. Supported commands: %s",
			ErrUnsupportedCommand, command, getSupportedCommandsList())
	}

	return nil
}

// isCommandSupported checks if the command is in the list of supported commands
func isCommandSupported(command string) bool {
	supportedCommands := map[string]bool{
		CommandFrunkOpen:   true,
		CommandTrunkOpen:   true,
		CommandDoorsLock:   true,
		CommandDoorsUnlock: true,
		CommandChargeStart: true,
		CommandChargeStop:  true,
	}

	return supportedCommands[command]
}

// getSupportedCommandsList returns a comma-separated list of supported commands for error messages
func getSupportedCommandsList() string {
	commands := []string{
		CommandFrunkOpen,
		CommandTrunkOpen,
		CommandDoorsLock,
		CommandDoorsUnlock,
		CommandChargeStart,
		CommandChargeStop,
	}

	return strings.Join(commands, ", ")
}

// getEventTypeForCommand returns the CloudEvent type for each Tesla command
// Based on legacy implementation: different commands have different event types
// so the consumer knows which Tesla API endpoint to call
func (ts *TeslaService) getEventTypeForCommand(command string) string {
	prefix := "zone.dimo.task.tesla"
	commandEventTypes := map[string]string{
		CommandFrunkOpen:   fmt.Sprintf("%s.frunk.open", prefix),
		CommandTrunkOpen:   fmt.Sprintf("%s.trunk.open", prefix),
		CommandDoorsLock:   fmt.Sprintf("%s.doors.lock", prefix),
		CommandDoorsUnlock: fmt.Sprintf("%s.doors.unlock", prefix),
		CommandChargeStart: fmt.Sprintf("%s.charge.start", prefix),
		CommandChargeStop:  fmt.Sprintf("%s.charge.stop", prefix),
	}

	if eventType, exists := commandEventTypes[command]; exists {
		return eventType
	}

	// Fallback to generic command type if command not found
	return "com.tesla.vehicle.command.generic"
}
