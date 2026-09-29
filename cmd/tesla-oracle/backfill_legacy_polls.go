package main

import (
	"context"
	"fmt"

	"github.com/DIMO-Network/tesla-oracle/internal/bootstrap"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	work "github.com/DIMO-Network/tesla-oracle/internal/workers"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/rs/zerolog"
)

func backfillLegacyPolls(ctx context.Context, logger *zerolog.Logger, settings *config.Settings) error {
	services, err := bootstrap.InitializeServices(ctx, logger, settings)
	if err != nil {
		return fmt.Errorf("initialize services: %w", err)
	}
	defer services.Cleanup()

	scheduler := work.NewLegacyTeslaPollScheduler(services.RiverClient, logger)

	// Pending covers legacy vehicles whose /start failed before the device was
	// marked active. Pending devices that need reauthentication fail the token
	// or fleet status check below and are skipped.
	var devices dbmodels.SyntheticDeviceSlice
	for _, status := range []string{"active", "pending"} {
		byStatus, err := services.Repositories.Vehicle.GetSyntheticDevicesBySubscriptionStatus(ctx, status)
		if err != nil {
			return fmt.Errorf("list %s synthetic devices: %w", status, err)
		}
		devices = append(devices, byStatus...)
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
			entry.Warn().Err(err).Msg("Skipping device; unable to get Tesla access token")
			continue
		}

		fleetStatus, err := services.TeslaFleetAPIService.VirtualKeyConnectionStatus(ctx, accessToken, device.Vin)
		if err != nil {
			skipped++
			entry.Warn().Err(err).Msg("Skipping device; unable to fetch Tesla fleet status")
			continue
		}

		decision, err := service.DecisionTreeAction(fleetStatus, int64(device.VehicleTokenID.Int))
		if err != nil {
			skipped++
			entry.Warn().Err(err).Msg("Skipping device; unable to classify telemetry mode")
			continue
		}

		if decision.Action != service.ActionStartPolling {
			entry.Debug().Str("action", decision.Action).Msg("Device is not legacy polling eligible")
			continue
		}

		matched++
		// The poll job stops on its first run for a device that isn't active.
		if device.SubscriptionStatus.String != "active" {
			if err := services.Repositories.Vehicle.UpdateSyntheticDeviceSubscriptionStatus(ctx, device, "active"); err != nil {
				skipped++
				entry.Warn().Err(err).Msg("Failed to mark device active")
				continue
			}
		}
		if err := scheduler.ScheduleLegacyPoll(ctx, device); err != nil {
			skipped++
			entry.Warn().Err(err).Msg("Failed to enqueue legacy polling job")
			continue
		}

		scheduled++
		entry.Info().Msg("Enqueued legacy polling job")
	}

	logger.Info().
		Int("devices", len(devices)).
		Int("matchedLegacy", matched).
		Int("scheduled", scheduled).
		Int("skipped", skipped).
		Msg("Completed legacy polling backfill")

	return nil
}
