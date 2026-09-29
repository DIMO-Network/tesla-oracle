package workers

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
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

// Work polls the vehicle once, then snoozes this job so the same job polls again
// after pollInterval. Inserting a follow-up job from here instead would be
// skipped as a duplicate of this running one and end the loop. Returning nil
// ends polling for the vehicle; a later /start schedules it again.
func (w *LegacyTeslaPollWorker) Work(ctx context.Context, job *river.Job[LegacyTeslaPollArgs]) error {
	logger := w.logger.With().
		Int("vehicleTokenId", job.Args.VehicleTokenID).
		Int64("jobId", job.ID).
		Logger()

	sd, err := w.vehicleRepo.GetSyntheticDeviceByTokenID(ctx, int64(job.Args.VehicleTokenID))
	if err != nil {
		if errors.Is(err, repository.ErrVehicleNotFound) {
			return nil
		}
		logger.Warn().Err(err).Msg("Failed to load synthetic device for legacy polling; will retry on next scheduled run")
		return river.JobSnooze(w.pollInterval)
	}

	if !shouldContinueLegacyPolling(sd) {
		return nil
	}

	logger = logger.With().Str("vin", sd.Vin).Logger()
	if !w.poll(ctx, &logger, sd) {
		return nil
	}

	return river.JobSnooze(w.pollInterval)
}

// poll fetches one legacy vehicle data sample and sends it to DIS. It reports
// whether polling should continue.
func (w *LegacyTeslaPollWorker) poll(ctx context.Context, logger *zerolog.Logger, sd *dbmodels.SyntheticDevice) bool {
	accessToken, err := w.tokenManager.GetOrRefreshAccessToken(ctx, sd)
	if err != nil {
		if w.shouldDisablePolling(err) {
			logger.Warn().Err(err).Msg("Stopping legacy polling until vehicle is reauthenticated")
			return !w.markPending(ctx, logger, sd)
		}

		logger.Warn().Err(err).Msg("Transient credential failure during legacy polling; will retry on next scheduled run")
		return true
	}

	rawStatus, err := w.teslaFleetAPI.GetLegacyVehicleData(ctx, accessToken, sd.Vin)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrVehicleUnavailable):
			logger.Debug().Msg("Vehicle unavailable for legacy polling; skipping send")
		case errors.Is(err, core.ErrFleetAPIUnauthorized):
			logger.Warn().Err(err).Msg("Stopping legacy polling after unauthorized Tesla response")
			return !w.markPending(ctx, logger, sd)
		default:
			logger.Warn().Err(err).Msg("Transient Tesla vehicle data failure during legacy polling; will retry on next scheduled run")
		}
		return true
	}

	if len(rawStatus) == 0 || json.RawMessage(rawStatus) == nil {
		return true
	}

	if err := w.sender.Send(ctx, sd, rawStatus); err != nil {
		logger.Warn().Err(err).Msg("Failed to send legacy vehicle data; will retry on next scheduled run")
	}

	return true
}

// markPending records that the vehicle needs reauthentication. It reports
// whether that was saved; when it wasn't, polling continues so the next run
// tries again.
func (w *LegacyTeslaPollWorker) markPending(ctx context.Context, logger *zerolog.Logger, sd *dbmodels.SyntheticDevice) bool {
	if sd.SubscriptionStatus.Valid && sd.SubscriptionStatus.String == "pending" {
		return true
	}
	if err := w.vehicleRepo.UpdateSyntheticDeviceSubscriptionStatus(ctx, sd, "pending"); err != nil {
		logger.Error().Err(err).Msg("Failed to mark vehicle pending; will retry on next scheduled run")
		return false
	}
	return true
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

func (w *LegacyTeslaPollWorker) shouldDisablePolling(err error) bool {
	if errors.Is(err, core.ErrTokenExpired) {
		return true
	}

	decision, decErr := service.TokenRefreshDecisionTree(err)
	if decErr != nil {
		return false
	}

	return decision.Action == service.ActionLoginRequired
}
