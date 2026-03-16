package workers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/rs/zerolog"
)

type LegacyTeslaPollArgs struct {
	VehicleTokenID int    `json:"vehicleTokenId" river:"unique"`
	VIN            string `json:"vin"`
}

func (LegacyTeslaPollArgs) Kind() string { return "tesla_legacy_poll" }

func (a LegacyTeslaPollArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: 1,
		Queue:       "tesla_polls",
		Priority:    2,
		UniqueOpts: river.UniqueOpts{
			ByArgs:  true,
			ByQueue: true,
			ByState: legacyPollUniqueStates(),
		},
	}
}

type LegacyTeslaPollWorker struct {
	river.WorkerDefaults[LegacyTeslaPollArgs]
	teslaFleetAPI core.TeslaFleetAPIService
	tokenManager  *core.TeslaTokenManager
	vehicleRepo   repository.VehicleRepository
	sender        *LegacyPollSender
	logger        *zerolog.Logger
	pollInterval  time.Duration
}

func NewLegacyTeslaPollWorker(
	teslaFleetAPI core.TeslaFleetAPIService,
	tokenManager *core.TeslaTokenManager,
	vehicleRepo repository.VehicleRepository,
	sender *LegacyPollSender,
	logger *zerolog.Logger,
	pollInterval time.Duration,
) *LegacyTeslaPollWorker {
	return &LegacyTeslaPollWorker{
		teslaFleetAPI: teslaFleetAPI,
		tokenManager:  tokenManager,
		vehicleRepo:   vehicleRepo,
		sender:        sender,
		logger:        logger,
		pollInterval:  pollInterval,
	}
}

func (w *LegacyTeslaPollWorker) Work(ctx context.Context, job *river.Job[LegacyTeslaPollArgs]) error {
	sd, err := w.vehicleRepo.GetSyntheticDeviceByTokenID(ctx, int64(job.Args.VehicleTokenID))
	if err != nil {
		if errors.Is(err, repository.ErrVehicleNotFound) {
			return nil
		}
		return fmt.Errorf("load synthetic device: %w", err)
	}

	if !shouldContinueLegacyPolling(sd) {
		return nil
	}

	logger := w.logger.With().
		Int("vehicleTokenId", job.Args.VehicleTokenID).
		Str("vin", sd.Vin).
		Int64("jobId", job.ID).
		Logger()

	accessToken, err := w.tokenManager.GetOrRefreshAccessToken(ctx, sd)
	if err != nil {
		if errors.Is(err, core.ErrTokenExpired) {
			logger.Warn().Err(err).Msg("Stopping legacy polling until vehicle is reauthenticated")
			return w.markPending(ctx, sd)
		}
		return fmt.Errorf("get access token: %w", err)
	}

	if err := w.scheduleNext(ctx, job.Args); err != nil {
		return fmt.Errorf("schedule next legacy poll: %w", err)
	}

	rawStatus, err := w.teslaFleetAPI.GetLegacyVehicleData(ctx, accessToken, sd.Vin)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrVehicleUnavailable):
			logger.Debug().Msg("Vehicle unavailable for legacy polling; skipping send")
			return nil
		case errors.Is(err, core.ErrFleetAPIUnauthorized):
			logger.Warn().Err(err).Msg("Stopping legacy polling after unauthorized Tesla response")
			return w.markPending(ctx, sd)
		default:
			return fmt.Errorf("fetch legacy vehicle data: %w", err)
		}
	}

	if len(rawStatus) == 0 || json.RawMessage(rawStatus) == nil {
		return nil
	}

	if err := w.sender.Send(ctx, sd, rawStatus); err != nil {
		return fmt.Errorf("send legacy vehicle data: %w", err)
	}

	return nil
}

func (w *LegacyTeslaPollWorker) scheduleNext(ctx context.Context, args LegacyTeslaPollArgs) error {
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return fmt.Errorf("get river client from context: %w", err)
	}

	res, err := client.Insert(ctx, args, &river.InsertOpts{
		ScheduledAt: nextLegacyPollTime(time.Now(), w.pollInterval),
	})
	if err != nil {
		return err
	}

	if res.UniqueSkippedAsDuplicate {
		w.logger.Debug().
			Int("vehicleTokenId", args.VehicleTokenID).
			Str("vin", args.VIN).
			Msg("Next legacy poll already scheduled")
	}

	return nil
}

func (w *LegacyTeslaPollWorker) markPending(ctx context.Context, sd *dbmodels.SyntheticDevice) error {
	if sd.SubscriptionStatus.Valid && sd.SubscriptionStatus.String == "pending" {
		return nil
	}
	return w.vehicleRepo.UpdateSyntheticDeviceSubscriptionStatus(ctx, sd, "pending")
}

func shouldContinueLegacyPolling(sd *dbmodels.SyntheticDevice) bool {
	if sd == nil {
		return false
	}
	if !sd.SubscriptionStatus.Valid || sd.SubscriptionStatus.String != "active" {
		return false
	}
	return sd.AccessToken.Valid && sd.RefreshToken.Valid
}
