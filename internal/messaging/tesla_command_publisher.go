package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/IBM/sarama"
	"github.com/rs/zerolog"
	"github.com/segmentio/ksuid"
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

// NewCommandPublisher creates a new CommandPublisher implementation
func NewCommandPublisher(producer sarama.SyncProducer, settings *config.Settings, logger *zerolog.Logger) CommandPublisher {
	return &CommandPublisherImpl{
		producer: producer,
		settings: settings,
		logger:   logger,
	}
}

// PublishCommand publishes a Tesla command to Kafka, so it will be picked up by the task worker
func (p *CommandPublisherImpl) PublishCommand(ctx context.Context, sd *dbmodels.SyntheticDevice, command string) (string, error) {
	// Generate unique task ID
	taskID := ksuid.New().String()

	eventType := p.getEventTypeForCommand(command)

	// Create command data
	cmdData := CommandData{
		TaskID:         taskID,
		VehicleTokenID: sd.VehicleTokenID.Int,
		VIN:            sd.Vin,
		Timestamp:      time.Now(),
	}

	event := cloudevent.CloudEvent[CommandData]{
		CloudEventHeader: cloudevent.CloudEventHeader{
			ID:          taskID,
			SpecVersion: "1.0",
			Type:        eventType,
			Source:      "tesla-oracle",
			Subject:     strconv.Itoa(sd.VehicleTokenID.Int),
			Time:        time.Now().UTC(),
		},
		Data: cmdData,
	}

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("failed to marshal command event: %w", err)
	}

	msg := &sarama.ProducerMessage{
		Topic: p.settings.TopicTeslaCommand,
		Key:   sarama.StringEncoder(strconv.Itoa(sd.VehicleTokenID.Int)), // Partition by vehicleTokenID
		Value: sarama.ByteEncoder(eventJSON),
	}

	partition, offset, err := p.producer.SendMessage(msg)
	if err != nil {
		return "", fmt.Errorf("failed to send message to Kafka: %w", err)
	}

	p.logger.Info().
		Str("taskId", taskID).
		Str("vin", sd.Vin).
		Str("command", command).
		Int32("partition", partition).
		Int64("offset", offset).
		Msg("Tesla command published to Kafka")

	return taskID, nil
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
