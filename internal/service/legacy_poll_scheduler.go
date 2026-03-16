package service

import (
	"context"

	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
)

type LegacyPollScheduler interface {
	ScheduleLegacyPoll(ctx context.Context, device *dbmodels.SyntheticDevice) error
}
