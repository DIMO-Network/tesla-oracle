package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/consumer"
	"github.com/DIMO-Network/tesla-oracle/internal/credlistener"
	"github.com/DIMO-Network/tesla-oracle/internal/telemetry"
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

	// Start telemetry consumer if configured
	if cm.services.DISClient != nil && cm.settings.TeslaTelemetryTopic != "" {
		if err := cm.startTelemetryConsumer(ctx, group); err != nil {
			return fmt.Errorf("failed to start telemetry consumer: %w", err)
		}
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

// startTelemetryConsumer starts the Tesla telemetry Kafka consumer that batches payloads and forwards them to DIS.
func (cm *ConsumerManager) startTelemetryConsumer(ctx context.Context, group *errgroup.Group) error {
	mapRefreshDur, err := time.ParseDuration(cm.settings.MappingRefreshInterval)
	if err != nil {
		return fmt.Errorf("couldn't parse MAPPING_REFRESH_INTERVAL %q: %w", cm.settings.MappingRefreshInterval, err)
	}

	saramaCfg := sarama.NewConfig()
	saramaCfg.Version = sarama.V3_6_0_0

	brokers := strings.Split(cm.settings.KafkaBrokers, ",")
	kClient, err := sarama.NewClient(brokers, saramaCfg)
	if err != nil {
		return fmt.Errorf("error creating kafka client for telemetry consumer: %w", err)
	}

	cGroup, err := sarama.NewConsumerGroupFromClient(cm.settings.TeslaTelemetryGroup, kClient)
	if err != nil {
		return fmt.Errorf("error creating telemetry consumer group: %w", err)
	}

	batcher := telemetry.NewBatcher(
		cm.services.DISClient,
		cm.services.WalletService,
		cm.settings.VehicleNftAddress,
		cm.settings.SyntheticNftAddress,
		cm.settings.TeslaConnectionAddr,
		cm.settings.ChainID,
		cm.logger,
	)
	vinMap := telemetry.NewVinMap(cm.services.DB.DBS, mapRefreshDur, cm.logger)
	proc := telemetry.NewProcessor(batcher, vinMap, cm.settings.TeslaTelemetryTopic, cm.settings.BatcherDurationSeconds, cm.logger)

	group.Go(func() error {
		for {
			cm.logger.Info().Msgf("starting telemetry consumer: %s", cm.settings.TeslaTelemetryTopic)
			if err := cGroup.Consume(ctx, strings.Split(cm.settings.TeslaTelemetryTopic, ","), proc); err != nil {
				if errors.Is(err, sarama.ErrClosedConsumerGroup) {
					return nil
				}
				cm.logger.Err(err).Msg("telemetry consumer failure")
				return err
			}
			if ctx.Err() != nil {
				return nil
			}
		}
	})

	cm.logger.Info().Msgf("Started telemetry consumer for topic: %s", cm.settings.TeslaTelemetryTopic)
	return nil
}
