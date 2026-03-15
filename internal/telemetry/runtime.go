package telemetry

import (
	"fmt"
	"time"

	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	"github.com/DIMO-Network/tesla-oracle/pkg/wallet"
	"github.com/rs/zerolog"
)

type Runtime struct {
	Processor *Processor
	Group     string
	Topic     string
}

func NewRuntime(settings *config.Settings, logger *zerolog.Logger, walletService wallet.SDWalletsAPI, lookup service.SyntheticDeviceLookupService) (*Runtime, error) {
	if settings.TeslaTelemetryTopic == "" {
		return nil, fmt.Errorf("TESLA_TELEMETRY_TOPIC is required")
	}
	if settings.TeslaTelemetryGroup == "" {
		return nil, fmt.Errorf("TESLA_TELEMETRY_GROUP is required")
	}
	if settings.TeslaConnectionAddr == "" {
		return nil, fmt.Errorf("TESLA_CONNECTION_ADDR is required")
	}
	if settings.TeslaDISHost == "" {
		return nil, fmt.Errorf("TESLA_DIS_HOST is required")
	}
	if settings.TeslaDISClientTLSCert == "" {
		return nil, fmt.Errorf("TESLA_DIS_CLIENT_TLS_CERT is required")
	}
	if settings.TeslaDISClientTLSKey == "" {
		return nil, fmt.Errorf("TESLA_DIS_CLIENT_TLS_KEY is required")
	}
	if settings.TeslaDISCACert == "" {
		return nil, fmt.Errorf("TESLA_DIS_CA_CERT is required")
	}

	mapRefreshDur, err := time.ParseDuration(settings.TelemetryMappingRefreshInterval)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse telemetry mapping refresh duration %q: %w", settings.TelemetryMappingRefreshInterval, err)
	}

	disClient, err := NewDISClient(
		settings.TeslaDISClientTLSCert,
		settings.TeslaDISClientTLSKey,
		settings.TeslaDISCACert,
		settings.TeslaDISHost,
		settings.TelemetryRetryBackoffSeconds,
		settings.TelemetryDISRetryLimit,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create DIS client: %w", err)
	}

	batcher := NewBatcher(
		disClient,
		walletService,
		settings.VehicleNftAddress,
		settings.SyntheticNftAddress,
		settings.TeslaConnectionAddr,
		settings.ChainID,
		logger,
	)
	vinMap := NewVINMap(lookup, mapRefreshDur, logger)

	logger.Info().Msgf("Refreshing telemetry mappings after %s.", mapRefreshDur)

	return &Runtime{
		Processor: NewProcessor(batcher, vinMap, settings.TeslaTelemetryTopic, settings.TelemetryBatcherDurationSeconds, logger),
		Group:     settings.TeslaTelemetryGroup,
		Topic:     settings.TeslaTelemetryTopic,
	}, nil
}
