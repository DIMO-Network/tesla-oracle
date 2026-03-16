package main

import (
	"context"
	"fmt"

	"github.com/DIMO-Network/tesla-oracle/internal/bootstrap"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	work "github.com/DIMO-Network/tesla-oracle/internal/workers"
	"github.com/rs/zerolog"
)

func backfillLegacyPolls(ctx context.Context, logger *zerolog.Logger, settings *config.Settings) error {
	services, err := bootstrap.InitializeServices(ctx, logger, settings)
	if err != nil {
		return fmt.Errorf("initialize services: %w", err)
	}
	defer services.Cleanup()

	scheduler := work.NewLegacyTeslaPollScheduler(services.RiverClient, logger)

	devices, err := services.Repositories.Vehicle.GetSyntheticDevicesBySubscriptionStatus(ctx, "active")
	if err != nil {
		return fmt.Errorf("list active synthetic devices: %w", err)
	}

	var (
		matched   int
		scheduled int
		skipped   int
	)

	for _, device := range devices {
		entry := logger.With().
			Str("vin", device.Vin).
			Int("vehicleTokenId", device.VehicleTokenID.Int).
			Int("syntheticTokenId", device.TokenID.Int).
			Logger()

		accessToken, err := services.TokenManager.GetOrRefreshAccessToken(ctx, device)
		if err != nil {
			skipped++
			entry.Warn().Err(err).Msg("Skipping active device; unable to get Tesla access token")
			continue
		}

		fleetStatus, err := services.TeslaFleetAPIService.VirtualKeyConnectionStatus(ctx, accessToken, device.Vin)
		if err != nil {
			skipped++
			entry.Warn().Err(err).Msg("Skipping active device; unable to fetch Tesla fleet status")
			continue
		}

		decision, err := service.DecisionTreeAction(fleetStatus, int64(device.VehicleTokenID.Int))
		if err != nil {
			skipped++
			entry.Warn().Err(err).Msg("Skipping active device; unable to classify telemetry mode")
			continue
		}

		if decision.Action != service.ActionStartPolling {
			entry.Debug().Str("action", decision.Action).Msg("Active device is not legacy polling eligible")
			continue
		}

		matched++
		if err := scheduler.ScheduleLegacyPoll(ctx, device); err != nil {
			skipped++
			entry.Warn().Err(err).Msg("Failed to enqueue legacy polling job")
			continue
		}

		scheduled++
		entry.Info().Msg("Enqueued legacy polling job")
	}

	logger.Info().
		Int("activeDevices", len(devices)).
		Int("matchedLegacy", matched).
		Int("scheduled", scheduled).
		Int("skipped", skipped).
		Msg("Completed legacy polling backfill")

	return nil
}
