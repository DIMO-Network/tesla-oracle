package workers

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/DIMO-Network/tesla-oracle/internal/commands"
	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	"github.com/riverqueue/river"
	"github.com/rs/zerolog"
)

const maxWakeUpAttempts = 5

// TeslaCommandArgs represents the arguments for a Tesla command job
type TeslaCommandArgs struct {
	VehicleTokenID int    `json:"vehicleTokenId"`
	VIN            string `json:"vin"`
	Command        string `json:"command"`
	WakeAttempts   int    `json:"wakeAttempts,omitempty"` // Track wake-up attempts
}

// Kind returns the job kind identifier for River
func (a TeslaCommandArgs) Kind() string { return "tesla_command" }

// InsertOpts configures how the job is inserted into the queue
func (a TeslaCommandArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: 3,                // Allow retries for command failures
		Queue:       "tesla_commands", // Dedicated queue
		Priority:    1,                // Normal priority
		UniqueOpts: river.UniqueOpts{
			ByArgs:  true, // Prevent duplicate commands
			ByQueue: true, // Within the same queue
		},
	}
}

// TeslaCommandWorker handles Tesla command execution with wake-up logic
type TeslaCommandWorker struct {
	river.WorkerDefaults[TeslaCommandArgs]
	teslaFleetAPI core.TeslaFleetAPIService
	tokenManager  *core.TeslaTokenManager
	commandRepo   repository.CommandRepository
	vehicleRepo   repository.VehicleRepository
	logger        *zerolog.Logger
}

// NewTeslaCommandWorker creates a new Tesla command worker
func NewTeslaCommandWorker(
	teslaFleetAPI core.TeslaFleetAPIService,
	tokenManger *core.TeslaTokenManager,
	commandRepo repository.CommandRepository,
	vehicleRepo repository.VehicleRepository,
	logger *zerolog.Logger,
) *TeslaCommandWorker {
	return &TeslaCommandWorker{
		teslaFleetAPI: teslaFleetAPI,
		tokenManager:  tokenManger,
		commandRepo:   commandRepo,
		vehicleRepo:   vehicleRepo,
		logger:        logger,
	}
}

// Work executes the Tesla command job
func (w *TeslaCommandWorker) Work(ctx context.Context, job *river.Job[TeslaCommandArgs]) error {
	args := job.Args

	jobID := strconv.FormatInt(job.ID, 10)

	logger := w.logger.With().
		Str("jobId", jobID).
		Int("vehicleTokenId", args.VehicleTokenID).
		Str("vin", args.VIN).
		Str("command", args.Command).
		Int("wakeAttempts", args.WakeAttempts).
		Logger()

	logger.Info().Msg("Starting Tesla command execution")

	// Get synthetic device to retrieve access token
	sd, err := w.vehicleRepo.GetSyntheticDeviceByTokenID(ctx, int64(args.VehicleTokenID))
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get synthetic device")
		// Don't update status here - let River handle retries
		return fmt.Errorf("failed to get synthetic device: %w", err)
	}

	// Get access token using TeslaService
	accessToken, err := w.tokenManager.GetOrRefreshAccessToken(ctx, sd)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get access token")
		// Don't update status here - let River handle retries
		return fmt.Errorf("failed to get access token: %w", err)
	}

	// Attempt to wake up vehicle and get its state
	vehicle, err := w.teslaFleetAPI.WakeUpVehicle(ctx, accessToken, args.VIN)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to wake up vehicle")
		// Don't update status here - let River handle retries
		return fmt.Errorf("failed to wake up vehicle: %w", err)
	}

	// Check if vehicle is awake
	if vehicle.State != "online" {

		if args.WakeAttempts >= maxWakeUpAttempts {
			errMsg := fmt.Sprintf("vehicle failed to wake up after %d attempts, final state: %s", args.WakeAttempts, vehicle.State)
			logger.Warn().Str("finalState", vehicle.State).Msg("Vehicle failed to wake up after maximum attempts")
			// This is a permanent failure - vehicle won't wake up, don't retry
			w.updateCommandStatus(ctx, jobID, commands.CommandStatusFailed, errMsg)
			return river.JobCancel(fmt.Errorf(errMsg))
		}

		// Vehicle is still not awake, increment wake attempts and snooze
		args.WakeAttempts++
		logger.Info().
			Str("currentState", vehicle.State).
			Int("nextWakeAttempt", args.WakeAttempts).
			Msg("Vehicle not awake, scheduling retry")

		// Update the job args for the next attempt
		job.Args = args
		return river.JobSnooze(1 * time.Minute) // Wait 1 minute before retrying
	}

	logger.Info().Str("vehicleState", vehicle.State).Msg("Vehicle is awake, executing command")

	// Vehicle is awake, execute the command
	err = w.executeCommand(ctx, accessToken, args.VIN, args.Command)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to execute command")
		// Don't update status here - let River handle retries
		return fmt.Errorf("failed to execute command: %w", err)
	}

	// Command executed successfully
	logger.Info().Msg("Tesla command executed successfully")
	w.updateCommandStatus(ctx, jobID, commands.CommandStatusCompleted, "")

	return nil
}

// executeCommand executes the actual Tesla command via Fleet API
func (w *TeslaCommandWorker) executeCommand(ctx context.Context, accessToken string, vin, command string) error {
	// TODO: Implement actual command execution based on command type
	// This is where you would call specific Tesla Fleet API endpoints
	// For now, we'll simulate the command execution

	w.logger.Info().
		Str("command", command).
		//Int("vehicleId", vehicleID).
		Msg("Executing Tesla command")

	// Simulate command execution time
	time.Sleep(2 * time.Second)

	// In a real implementation, you would:
	// 1. Parse the command type (frunk/open, doors/lock, etc.)
	// 2. Call the appropriate Tesla Fleet API endpoint
	// 3. Handle the response and potential errors

	return nil
}

// updateCommandStatus updates the command status in the database
func (w *TeslaCommandWorker) updateCommandStatus(ctx context.Context, jobID, status, errorMessage string) {
	// Get the existing command request
	commandRequest, err := w.commandRepo.GetCommandRequest(ctx, jobID)
	if err != nil {
		w.logger.Error().Err(err).
			Str("jobId", jobID).
			Msg("Failed to get command request")
		return
	}

	// Update the status and error message
	commandRequest.Status = status
	if errorMessage != "" {
		commandRequest.ErrorMessage.SetValid(errorMessage)
	}

	// Save the updated request
	err = w.commandRepo.UpdateCommandRequest(ctx, commandRequest)
	if err != nil {
		w.logger.Error().Err(err).
			Str("jobId", jobID).
			Str("status", status).
			Msg("Failed to update command status")
	}
}
