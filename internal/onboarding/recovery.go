package onboarding

import (
	"context"
	"time"

	"github.com/DIMO-Network/tesla-oracle/internal/service"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
)

// MintRecoveryInterval is how often MintRecoveryWorker runs.
const MintRecoveryInterval = 5 * time.Minute

// MintRecoveryArgs are the arguments of the periodic MintRecoveryWorker job.
type MintRecoveryArgs struct{}

func (MintRecoveryArgs) Kind() string {
	return "onboard_recovery"
}

// InsertOpts: a failed run isn't retried, the next period runs again.
func (MintRecoveryArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{MaxAttempts: 1}
}

// NewMintRecoveryPeriodicJob runs MintRecoveryWorker every MintRecoveryInterval,
// starting when the client does.
func NewMintRecoveryPeriodicJob() *river.PeriodicJob {
	return river.NewPeriodicJob(
		river.PeriodicInterval(MintRecoveryInterval),
		func() (river.JobArgs, *river.InsertOpts) { return MintRecoveryArgs{}, nil },
		&river.PeriodicJobOpts{RunOnStart: true},
	)
}

// MintRecoveryWorker settles the records of mint jobs that died. A pod killed
// mid-mint leaves its job running until River's rescuer discards it, with no error
// handler and no log, and leaves its record looking like a mint in progress, which
// is never submitted again. This logs each such mint and settles its record.
type MintRecoveryWorker struct {
	recovery *service.MintRecovery

	river.WorkerDefaults[MintRecoveryArgs]
}

func NewMintRecoveryWorker(recovery *service.MintRecovery) *MintRecoveryWorker {
	return &MintRecoveryWorker{recovery: recovery}
}

func (w *MintRecoveryWorker) Work(ctx context.Context, _ *river.Job[MintRecoveryArgs]) error {
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return err
	}
	return w.recovery.RecoverAll(ctx, client)
}
