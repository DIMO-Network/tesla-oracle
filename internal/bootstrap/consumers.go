package bootstrap

import (
	"context"
	"errors"
	"fmt"

	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/consumer"
	"github.com/DIMO-Network/tesla-oracle/internal/credlistener"
	"github.com/IBM/sarama"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
)

// ConsumerManager manages Kafka consumers
type ConsumerManager struct {
	settings *config.Settings
	logger   *zerolog.Logger
	services *Services
}

// NewConsumerManager creates a new consumer manager
func NewConsumerManager(settings *config.Settings, logger *zerolog.Logger, services *Services) *ConsumerManager {
	return &ConsumerManager{
		settings: settings,
		logger:   logger,
		services: services,
	}
}

// StartConsumers starts all Kafka consumers
func (cm *ConsumerManager) StartConsumers(ctx context.Context, group *errgroup.Group) error {
	// Start contract event consumer if enabled
	if cm.settings.EnableContractEventConsumer {
		if err := cm.startContractEventConsumer(ctx, group); err != nil {
			return fmt.Errorf("failed to start contract event consumer: %w", err)
		}
	}

	// Start credential listener
	if err := cm.startCredentialListener(ctx, group); err != nil {
		return fmt.Errorf("failed to start credential listener: %w", err)
	}

	return nil
}

// startContractEventConsumer starts the contract event consumer
func (cm *ConsumerManager) startContractEventConsumer(ctx context.Context, group *errgroup.Group) error {
	config := sarama.NewConfig()
	config.Version = sarama.V3_6_0_0

	cGroup, err := sarama.NewConsumerGroup([]string{cm.settings.KafkaBrokers}, cm.settings.TopicContractEvent, config)
	if err != nil {
		return fmt.Errorf("error creating consumer group: %w", err)
	}

	proc := consumer.New(*cm.services.DB, cm.services.TeslaService, cm.settings.TopicContractEvent, cm.settings.VehicleNftAddress, cm.logger)

	group.Go(func() error {
		return cm.runContractEventConsumer(ctx, proc, cGroup, cm.settings.TopicContractEvent)
	})

	cm.logger.Info().Msgf("Started contract event consumer for topic: %s", cm.settings.TopicContractEvent)
	return nil
}

// startCredentialListener starts the credential listener
func (cm *ConsumerManager) startCredentialListener(ctx context.Context, group *errgroup.Group) error {
	config := sarama.NewConfig()
	config.Version = sarama.V3_6_0_0

	cGroup, err := sarama.NewConsumerGroup([]string{cm.settings.KafkaBrokers}, "tesla-oracle", config)
	if err != nil {
		return fmt.Errorf("error creating consumer group: %w", err)
	}

	cl := credlistener.New(*cm.services.DB, cm.logger)

	group.Go(func() error {
		for {
			err := cGroup.Consume(ctx, []string{cm.settings.CredentialKTable}, cl)
			if err != nil {
				cm.logger.Warn().Err(err).Msg("Credential consumer error.")
			}
			if ctx.Err() != nil {
				return nil
			}
		}
	})

	cm.logger.Info().Msgf("Started credential listener for topic: %s", cm.settings.CredentialKTable)
	return nil
}

// runContractEventConsumer runs the contract event consumer with retry logic
func (cm *ConsumerManager) runContractEventConsumer(ctx context.Context, proc *consumer.Processor, consumer sarama.ConsumerGroup, topic string) error {
	for {
		cm.logger.Info().Msgf("starting consumer: %s", topic)
		if err := consumer.Consume(ctx, []string{topic}, proc); err != nil {
			if errors.Is(err, sarama.ErrClosedConsumerGroup) {
				return nil
			}
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}
