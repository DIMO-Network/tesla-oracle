package messaging

import (
	"context"

	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
)

// CommandPublisher handles publishing Tesla command messages
type CommandPublisher interface {
	PublishCommand(ctx context.Context, sd *dbmodels.SyntheticDevice, command string) (taskID string, err error)
}
