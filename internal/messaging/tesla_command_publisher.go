package messaging

import (
	"fmt"
	"time"

	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/IBM/sarama"
	"github.com/rs/zerolog"
)

type CommandData struct {
	TaskID         string    `json:"taskId"`
	VehicleTokenID int       `json:"vehicleTokenId"`
	VIN            string    `json:"vin"`
	Timestamp      time.Time `json:"timestamp"`
}

type CommandPublisherImpl struct {
	producer sarama.SyncProducer
	settings *config.Settings
	logger   *zerolog.Logger
}

// getEventTypeForCommand returns the CloudEvent type for each Tesla command
func (p *CommandPublisherImpl) getEventTypeForCommand(command string) string {
	prefix := "zone.dimo.task.tesla"
	commandEventTypes := map[string]string{
		"frunk/open":   fmt.Sprintf("%s.frunk.open", prefix),
		"trunk/open":   fmt.Sprintf("%s.trunk.open", prefix),
		"doors/lock":   fmt.Sprintf("%s.doors.lock", prefix),
		"doors/unlock": fmt.Sprintf("%s.doors.unlock", prefix),
		"charge/start": fmt.Sprintf("%s.charge.start", prefix),
		"charge/stop":  fmt.Sprintf("%s.charge.stop", prefix),
	}

	if eventType, exists := commandEventTypes[command]; exists {
		return eventType
	}

	// Fallback to generic command type if command not found
	return "com.tesla.vehicle.command.generic"
}
