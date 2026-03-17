package main

import (
	"context"
	"fmt"
	"strconv"

	"github.com/DIMO-Network/tesla-oracle/internal/bootstrap"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/rs/zerolog"
)

func ensureVehicleDataFlow(ctx context.Context, logger *zerolog.Logger, settings *config.Settings, vehicleTokenID int64) error {
	services, err := bootstrap.InitializeServices(ctx, logger, settings)
	if err != nil {
		return fmt.Errorf("initialize services: %w", err)
	}
	defer services.Cleanup()

	log := logger.With().
		Int64("vehicleTokenId", vehicleTokenID).
		Logger()

	if err := services.TeslaService.EnsureVehicleDataFlow(ctx, vehicleTokenID); err != nil {
		return err
	}

	log.Info().Msg("Ensured vehicle data flow")
	return nil
}

func parseVehicleTokenIDArg(args []string) (int64, error) {
	if len(args) < 3 {
		return 0, fmt.Errorf("usage: ensure-data-flow <vehicleTokenId>")
	}

	tokenID, err := strconv.ParseInt(args[2], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid vehicle token id %q: %w", args[2], err)
	}

	return tokenID, nil
}
