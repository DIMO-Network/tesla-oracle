package repository

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/DIMO-Network/shared/pkg/db"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/aarondl/sqlboiler/v4/queries/qm"
	"github.com/rs/zerolog"
)

// CommandRepositoryImpl implements CommandRepository interface
type CommandRepositoryImpl struct {
	DB     *db.Store
	logger *zerolog.Logger
}

// NewCommandRepository creates a new CommandRepository implementation
func NewCommandRepository(db *db.Store, logger *zerolog.Logger) CommandRepository {
	return &CommandRepositoryImpl{
		DB:     db,
		logger: logger,
	}
}

// SaveCommandRequest saves a new command request to the database
func (r *CommandRepositoryImpl) SaveCommandRequest(ctx context.Context, request *dbmodels.DeviceCommandRequest) error {
	// Set timestamps if not already set
	if request.CreatedAt.IsZero() {
		request.CreatedAt = time.Now()
	}
	if request.UpdatedAt.IsZero() {
		request.UpdatedAt = time.Now()
	}

	err := request.Insert(ctx, r.DB.DBS().Writer, boil.Infer())
	if err != nil {
		return fmt.Errorf("failed to insert command request: %w", err)
	}

	r.logger.Debug().
		Str("taskId", request.ID).
		Str("vehicleTokenId", strconv.Itoa(request.VehicleTokenID)).
		Str("command", request.Command).
		Msg("Command request saved to database")

	return nil
}

// UpdateCommandRequest updates an existing command request
func (r *CommandRepositoryImpl) UpdateCommandRequest(ctx context.Context, request *dbmodels.DeviceCommandRequest) error {
	// Always update the timestamp
	request.UpdatedAt = time.Now()

	_, err := request.Update(ctx, r.DB.DBS().Writer, boil.Infer())
	if err != nil {
		return fmt.Errorf("failed to update command request: %w", err)
	}

	r.logger.Debug().
		Str("taskId", request.ID).
		Str("status", request.Status).
		Msg("Command request updated")

	return nil
}

// GetCommandRequest retrieves a command request by task ID
func (r *CommandRepositoryImpl) GetCommandRequest(ctx context.Context, taskID string) (*dbmodels.DeviceCommandRequest, error) {
	commandRequest, err := dbmodels.FindDeviceCommandRequest(ctx, r.DB.DBS().Reader, taskID)
	if err != nil {
		return nil, fmt.Errorf("failed to find command request: %w", err)
	}

	return commandRequest, nil
}

// GetCommandRequestsByVehicle retrieves command requests for a specific vehicle
func (r *CommandRepositoryImpl) GetCommandRequestsByVehicle(ctx context.Context, vehicleTokenID int, limit int) (dbmodels.DeviceCommandRequestSlice, error) {
	commandRequests, err := dbmodels.DeviceCommandRequests(
		dbmodels.DeviceCommandRequestWhere.VehicleTokenID.EQ(vehicleTokenID),
		qm.OrderBy(dbmodels.DeviceCommandRequestColumns.CreatedAt+" DESC"),
		qm.Limit(limit),
	).All(ctx, r.DB.DBS().Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to get command requests for vehicle: %w", err)
	}

	return commandRequests, nil
}
