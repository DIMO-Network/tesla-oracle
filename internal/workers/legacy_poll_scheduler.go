package workers

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/rs/zerolog"

	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
)

type LegacyTeslaPollScheduler struct {
	riverClient *river.Client[pgx.Tx]
	logger      *zerolog.Logger
}

func NewLegacyTeslaPollScheduler(riverClient *river.Client[pgx.Tx], logger *zerolog.Logger) *LegacyTeslaPollScheduler {
	return &LegacyTeslaPollScheduler{
		riverClient: riverClient,
		logger:      logger,
	}
}

func (s *LegacyTeslaPollScheduler) ScheduleLegacyPoll(ctx context.Context, device *dbmodels.SyntheticDevice) error {
	if device == nil || !device.VehicleTokenID.Valid {
		return fmt.Errorf("synthetic device missing vehicle token id")
	}

	res, err := s.riverClient.Insert(ctx, LegacyTeslaPollArgs{
		VehicleTokenID: device.VehicleTokenID.Int,
		VIN:            device.Vin,
	}, nil)
	if err != nil {
		return fmt.Errorf("insert legacy poll job: %w", err)
	}

	logger := s.logger.With().
		Int("vehicleTokenId", device.VehicleTokenID.Int).
		Str("vin", device.Vin).
		Logger()

	if res.UniqueSkippedAsDuplicate {
		logger.Debug().Msg("Legacy poll job already scheduled")
		return nil
	}

	logger.Debug().Int64("jobId", res.Job.ID).Msg("Scheduled legacy poll job")
	return nil
}

func legacyPollUniqueStates() []rivertype.JobState {
	return []rivertype.JobState{
		rivertype.JobStateAvailable,
		rivertype.JobStatePending,
		rivertype.JobStateRetryable,
		rivertype.JobStateScheduled,
	}
}

func nextLegacyPollTime(now time.Time, interval time.Duration) time.Time {
	return now.UTC().Add(interval)
}
