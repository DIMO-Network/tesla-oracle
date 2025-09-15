package workers

import (
	"context"
	"fmt"
	"strconv"

	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/rs/zerolog"
)

// TeslaCommandErrorHandler handles errors and final failures for Tesla command jobs
type TeslaCommandErrorHandler struct {
	logger       zerolog.Logger
	repositories *repository.Repositories
}

// NewTeslaCommandErrorHandler creates a new Tesla command error handler
func NewTeslaCommandErrorHandler(logger zerolog.Logger, repositories *repository.Repositories) *TeslaCommandErrorHandler {
	return &TeslaCommandErrorHandler{
		logger:       logger,
		repositories: repositories,
	}
}

// HandleError handles final job failures and updates command status accordingly
func (h *TeslaCommandErrorHandler) HandleError(ctx context.Context, job *rivertype.JobRow, err error) *river.ErrorHandlerResult {
	// Handle final failures for Tesla command jobs
	// Somehow jobState not updated to discarded here, so we check both
	//if job.Kind == "tesla_command" && job.State == rivertype.JobStateDiscarded {
	if job.Kind == "tesla_command" && job.Attempt == job.MaxAttempts {

		h.logger.Error().
			Int64("jobId", job.ID).
			Str("jobKind", job.Kind).
			Err(err).
			Msg("Tesla command job permanently failed, updating status")

		// Update command status to failed
		jobID := strconv.FormatInt(job.ID, 10)
		commandRequest, getErr := h.repositories.Command.GetCommandRequest(ctx, jobID)
		if getErr != nil {
			h.logger.Error().Err(getErr).
				Str("jobId", jobID).
				Msg("Failed to get command request for failed job")
			return nil
		}

		// Update status to failed with error message
		commandRequest.Status = core.CommandStatusFailed
		if err != nil {
			commandRequest.ErrorMessage.SetValid(err.Error())
		}

		updateErr := h.repositories.Command.UpdateCommandRequest(ctx, commandRequest)
		if updateErr != nil {
			h.logger.Error().Err(updateErr).
				Str("jobId", jobID).
				Msg("Failed to update command status for failed job")
		}
	}
	return nil
}

// HandlePanic handles job panics and updates command status accordingly
func (h *TeslaCommandErrorHandler) HandlePanic(ctx context.Context, job *rivertype.JobRow, panicVal any, trace string) *river.ErrorHandlerResult {
	// Handle panics in Tesla command jobs
	if job.Kind == "tesla_command" {
		h.logger.Error().
			Int64("jobId", job.ID).
			Str("jobKind", job.Kind).
			Interface("panicVal", panicVal).
			Str("trace", trace).
			Msg("Tesla command job panicked, updating status")

		// Update command status to failed
		jobID := strconv.FormatInt(job.ID, 10)
		commandRequest, getErr := h.repositories.Command.GetCommandRequest(ctx, jobID)
		if getErr != nil {
			h.logger.Error().Err(getErr).
				Str("jobId", jobID).
				Msg("Failed to get command request for panicked job")
			return nil
		}

		// Update status to failed with panic info
		commandRequest.Status = core.CommandStatusFailed
		panicMsg := fmt.Sprintf("Job panicked: %v", panicVal)
		commandRequest.ErrorMessage.SetValid(panicMsg)

		updateErr := h.repositories.Command.UpdateCommandRequest(ctx, commandRequest)
		if updateErr != nil {
			h.logger.Error().Err(updateErr).
				Str("jobId", jobID).
				Msg("Failed to update command status for panicked job")
		}
	}
	return nil
}
