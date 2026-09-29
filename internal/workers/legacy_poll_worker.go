package workers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/rs/zerolog"
)

type LegacyTeslaPollArgs struct {
	VehicleTokenID int    `json:"vehicleTokenId" river:"unique"`
	VIN            string `json:"vin"`
}

func (LegacyTeslaPollArgs) Kind() string { return "tesla_legacy_poll" }

func (a LegacyTeslaPollArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		// Attempts are only used when a run fails before it schedules the next
		// poll (see Work). Each run is a new job, so this is per poll.
		MaxAttempts: 25,
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
	dbPool        *pgxpool.Pool
	teslaFleetAPI core.TeslaFleetAPIService
	tokenManager  *core.TeslaTokenManager
	vehicleRepo   repository.VehicleRepository
	sender        *LegacyPollSender
	logger        *zerolog.Logger
	pollInterval  time.Duration
}

func NewLegacyTeslaPollWorker(
	dbPool *pgxpool.Pool,
	teslaFleetAPI core.TeslaFleetAPIService,
	tokenManager *core.TeslaTokenManager,
	vehicleRepo repository.VehicleRepository,
	sender *LegacyPollSender,
	logger *zerolog.Logger,
	pollInterval time.Duration,
) *LegacyTeslaPollWorker {
	return &LegacyTeslaPollWorker{
		dbPool:        dbPool,
		teslaFleetAPI: teslaFleetAPI,
		tokenManager:  tokenManager,
		vehicleRepo:   vehicleRepo,
		sender:        sender,
		logger:        logger,
		pollInterval:  pollInterval,
	}
}

// NextRetry retries a run that failed before it scheduled the next poll (a DB
// error, a panic, a pod lost mid-run) at the poll interval rather than River's
// exponential backoff.
func (w *LegacyTeslaPollWorker) NextRetry(*river.Job[LegacyTeslaPollArgs]) time.Time {
	return time.Now().Add(w.pollInterval)
}

// Work polls the vehicle once. Before calling Tesla it completes this job and
// inserts the next poll in one transaction, so nothing that goes wrong during the
// poll, including losing the pod, can end polling for the vehicle. Returning
// before that ends polling; a later /start schedules it again.
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
		return fmt.Errorf("load synthetic device: %w", err)
	}

	if !shouldContinueLegacyPolling(sd) {
		return nil
	}

	if err := w.scheduleNext(ctx, job); err != nil {
		return fmt.Errorf("schedule next legacy poll: %w", err)
	}

	logger = logger.With().Str("vin", sd.Vin).Logger()
	w.poll(ctx, &logger, sd)

	return nil
}

// scheduleNext completes this job and inserts the vehicle's next poll in one
// transaction. This job has to be completed first: the next poll has the same
// unique args, and a running job counts as a duplicate.
func (w *LegacyTeslaPollWorker) scheduleNext(ctx context.Context, job *river.Job[LegacyTeslaPollArgs]) error {
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return fmt.Errorf("get river client from context: %w", err)
	}

	tx, err := w.dbPool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	if _, err := river.JobCompleteTx[*riverpgxv5.Driver](ctx, tx, job); err != nil {
		return fmt.Errorf("complete job: %w", err)
	}

	if _, err := client.InsertTx(ctx, tx, job.Args, &river.InsertOpts{
		ScheduledAt: time.Now().Add(w.pollInterval),
	}); err != nil {
		return fmt.Errorf("insert next poll: %w", err)
	}

	return tx.Commit(ctx)
}

// poll fetches one legacy vehicle data sample and sends it to DIS. Failures are
// logged and left to the next scheduled poll. When Tesla needs the vehicle
// reauthenticated, the device is marked pending, which ends polling on the next
// run.
func (w *LegacyTeslaPollWorker) poll(ctx context.Context, logger *zerolog.Logger, sd *dbmodels.SyntheticDevice) {
	accessToken, err := w.tokenManager.GetOrRefreshAccessToken(ctx, sd)
	if err != nil {
		if w.shouldDisablePolling(err) {
			logger.Warn().Err(err).Msg("Stopping legacy polling until vehicle is reauthenticated")
			w.markPending(ctx, logger, sd)
			return
		}

		logger.Warn().Err(err).Msg("Transient credential failure during legacy polling; will retry on next scheduled run")
		return
	}

	rawStatus, err := w.teslaFleetAPI.GetLegacyVehicleData(ctx, accessToken, sd.Vin)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrVehicleUnavailable):
			logger.Debug().Msg("Vehicle unavailable for legacy polling; skipping send")
		case errors.Is(err, core.ErrFleetAPIUnauthorized):
			logger.Warn().Err(err).Msg("Stopping legacy polling after unauthorized Tesla response")
			w.markPending(ctx, logger, sd)
		default:
			logger.Warn().Err(err).Msg("Transient Tesla vehicle data failure during legacy polling; will retry on next scheduled run")
		}
		return
	}

	if len(rawStatus) == 0 || json.RawMessage(rawStatus) == nil {
		return
	}

	if err := w.sender.Send(ctx, sd, rawStatus); err != nil {
		logger.Warn().Err(err).Msg("Failed to send legacy vehicle data; will retry on next scheduled run")
	}
}

// markPending records that the vehicle needs reauthentication. If that fails,
// the next run polls again and retries it.
func (w *LegacyTeslaPollWorker) markPending(ctx context.Context, logger *zerolog.Logger, sd *dbmodels.SyntheticDevice) {
	if sd.SubscriptionStatus.Valid && sd.SubscriptionStatus.String == "pending" {
		return
	}
	if err := w.vehicleRepo.UpdateSyntheticDeviceSubscriptionStatus(ctx, sd, "pending"); err != nil {
		logger.Error().Err(err).Msg("Failed to mark vehicle pending; will retry on next scheduled run")
	}
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
