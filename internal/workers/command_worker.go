package workers

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	"github.com/riverqueue/river"
	"github.com/rs/zerolog"
)

// We will attempt to wake up the vehicle this many times before giving up
const maxWakeUpAttempts = 1

// TeslaCommandArgs represents the arguments for a Tesla command job
type TeslaCommandArgs struct {
	VehicleTokenID int    `json:"vehicleTokenId"`
	VIN            string `json:"vin"`
	Command        string `json:"command"`
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
	teslaFleetAPI  core.TeslaFleetAPIService
	tokenManager   *core.TeslaTokenManager
	commandRepo    repository.CommandRepository
	vehicleRepo    repository.VehicleRepository
	logger         *zerolog.Logger
	SnoozeDuration time.Duration
}

// NewTeslaCommandWorker creates a new Tesla command worker
func NewTeslaCommandWorker(
	teslaFleetAPI core.TeslaFleetAPIService,
	tokenManager *core.TeslaTokenManager,
	commandRepo repository.CommandRepository,
	vehicleRepo repository.VehicleRepository,
	logger *zerolog.Logger,
	snoozeDuration time.Duration,
) *TeslaCommandWorker {
	return &TeslaCommandWorker{
		teslaFleetAPI:  teslaFleetAPI,
		tokenManager:   tokenManager,
		commandRepo:    commandRepo,
		vehicleRepo:    vehicleRepo,
		logger:         logger,
		SnoozeDuration: snoozeDuration,
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
		Logger()

	logger.Debug().Msg("Starting Tesla command execution")

	// Get current command request to check wake attempts
	commandRequest, err := w.commandRepo.GetCommandRequest(ctx, jobID)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get command request")
		// Don't update status here - let River handle retries

		return fmt.Errorf("failed to get command request: %w", err)
	}

	currentWakeAttempts := commandRequest.WakeAttempts
	logger = logger.With().Int("wakeAttempts", currentWakeAttempts).Logger()

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
		if currentWakeAttempts >= maxWakeUpAttempts {
			errMsg := fmt.Sprintf("vehicle failed to wake up after %d attempts, final state: %s", currentWakeAttempts+1, vehicle.State)
			logger.Warn().Str("finalState", vehicle.State).Int("wakeAttempts", currentWakeAttempts).Msg("Vehicle failed to wake up after maximum attempts")
			// This is a permanent failure - vehicle won't wake up, don't retry
			w.updateCommandStatus(ctx, jobID, core.CommandStatusFailed, errMsg)
			return river.JobCancel(fmt.Errorf("%s", errMsg))
		}

		// Vehicle is still not awake, increment wake attempts in database and snooze
		nextWakeAttempts := currentWakeAttempts + 1
		logger.Debug().
			Str("currentState", vehicle.State).
			Int("nextWakeAttempts", nextWakeAttempts).
			Int("maxAttempts", maxWakeUpAttempts).
			Msg("Vehicle not awake, incrementing wake attempts and scheduling retry")

		// Update wake attempts in database
		commandRequest.WakeAttempts = nextWakeAttempts
		err = w.commandRepo.UpdateCommandRequest(ctx, commandRequest)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to update wake attempts in database")
			return fmt.Errorf("failed to update wake attempts: %w", err)
		}

		// Snooze for 1 minute and let River retry the same job
		return river.JobSnooze(w.SnoozeDuration)
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
	w.updateCommandStatus(ctx, jobID, core.CommandStatusCompleted, "")

	return nil
}

// executeCommand executes the actual Tesla command via Fleet API
func (w *TeslaCommandWorker) executeCommand(ctx context.Context, accessToken string, vin, command string) error {
	w.logger.Info().
		Str("command", command).
		Str("vin", vin).
		Msg("Executing Tesla command")

	// Execute the command using TeslaFleetAPIService
	err := w.teslaFleetAPI.ExecuteCommand(ctx, accessToken, vin, command)
	if err != nil {
		return fmt.Errorf("failed to execute Tesla command %s: %w", command, err)
	}

	w.logger.Info().
		Str("command", command).
		Str("vin", vin).
		Msg("Tesla command executed successfully")

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
