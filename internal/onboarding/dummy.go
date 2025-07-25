package onboarding

import (
	"context"

	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/riverqueue/river"
	"github.com/rs/zerolog"
)

type DummyArgs struct {
}

func (a DummyArgs) Kind() string {
	return "dummy"
}

func (DummyArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		UniqueOpts: river.UniqueOpts{
			ByArgs: false,
		},
	}
}

type DummyWorker struct {
	settings *config.Settings
	logger   zerolog.Logger

	river.WorkerDefaults[DummyArgs]
}

func NewDummyWorker(settings *config.Settings, logger zerolog.Logger) *DummyWorker {
	return &DummyWorker{
		settings: settings,
		logger:   logger,
	}
}

func (w *DummyWorker) Work(ctx context.Context, job *river.Job[DummyArgs]) error {
	return nil
}
