package controllers

import (
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

type VehicleController struct {
	logger                *zerolog.Logger
	vehicleOnboardService service.VehicleOnboardService
}

func NewVehicleOnboardController(logger *zerolog.Logger, vehicleOnboardService service.VehicleOnboardService) *VehicleController {
	return &VehicleController{
		logger:                logger,
		vehicleOnboardService: vehicleOnboardService,
	}
}

// VerifyVins godoc
// @Summary     Verify vehicle before onboarding
// @Description Verifies vehicle before onboarding. In case of already minted vehicle checks ownership, synthetic token ID (should be empty), etc.
// @Tags        onboarding,verify
// @Accept      json
// @Produce     json
// @Param       payload body controllers.VinsVerifyParams true "Vehicles to verify"
// @Security    BearerAuth
// @Success     200 {object} controllers.StatusForVinsResponse
// @Failure     400 {object} fiber.Error "Bad Request"
// @Failure     401 {object} fiber.Error "Unauthorized"
// @Failure     500 {object} fiber.Error "Internal server error"
// @Router      /v1/vehicle/verify [post]
func (v *VehicleController) VerifyVins(c *fiber.Ctx) error {
	walletAddress := c.Locals("wallet").(common.Address)

	params := new(VinsVerifyParams)
	if err := c.BodyParser(params); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse VINs",
		})
	}

	statuses, err := v.vehicleOnboardService.VerifyVins(c.Context(), params.Vins, walletAddress)
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to verify VINs")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(StatusForVinsResponse{
		Statuses: statuses,
	})
}

// GetMintDataForVins godoc
// @Summary     Get minting payload for signing
// @Description Gets minting payload for signing. Only `typedData` field is populated in the response.
// @Tags        onboarding,mint
// @Accept      json
// @Produce     json
// @Param       vins query []string true "VINs"
// @Security    BearerAuth
// @Success     200 {object} controllers.MintDataForVins "Only `typedData` field is populated for each item"
// @Failure     400 {object} fiber.Error "Bad Request"
// @Failure     401 {object} fiber.Error "Unauthorized"
// @Failure     500 {object} fiber.Error "Internal server error"
// @Router      /v1/vehicle/mint [get]
func (v *VehicleController) GetMintDataForVins(c *fiber.Ctx) error {
	params := new(VinsGetParams)
	if err := c.QueryParser(params); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse VINs",
		})
	}

	mintingData, err := v.vehicleOnboardService.GetMintDataForVins(c.Context(), params.Vins)
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to get mint data for VINs")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(MintDataForVins{
		VinMintingData: mintingData,
	})
}

// SubmitMintDataForVins godoc
// @Summary     Submit signed data and sacd to mint
// @Description Submits signed data and sacd and triggers minting job start.
// @Tags        onboarding,mint
// @Accept      json
// @Produce     json
// @Param       payload body controllers.MintDataForVins true "Signed typed data and sacd for minting"
// @Security    BearerAuth
// @Success     200 {object} controllers.StatusForVinsResponse
// @Failure     400 {object} fiber.Error "Bad Request"
// @Failure     401 {object} fiber.Error "Unauthorized"
// @Failure     500 {object} fiber.Error "Internal server error"
// @Router      /v1/vehicle/mint [post]
func (v *VehicleController) SubmitMintDataForVins(c *fiber.Ctx) error {
	walletAddress := c.Locals("wallet").(common.Address)

	params := new(MintDataForVins)
	if err := c.BodyParser(params); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse minting data",
		})
	}

	statuses, err := v.vehicleOnboardService.SubmitMintDataForVins(c.Context(), params.VinMintingData, walletAddress)
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to submit mint data for VINs")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(StatusForVinsResponse{
		Statuses: statuses,
	})
}

// GetMintStatusForVins godoc
// @Summary     Get minting status
// @Description Gets status of minting jobs for provided VINs. Can be polled to wait for all minting jobs.
// @Tags        onboarding,mint
// @Accept      json
// @Produce     json
// @Param       vins query []string true "VINs"
// @Security    BearerAuth
// @Success     200 {object} controllers.StatusForVinsResponse
// @Failure     400 {object} fiber.Error "Bad Request"
// @Failure     401 {object} fiber.Error "Unauthorized"
// @Failure     500 {object} fiber.Error "Internal server error"
// @Router      /v1/vehicle/mint/status [get]
func (v *VehicleController) GetMintStatusForVins(c *fiber.Ctx) error {
	params := new(VinsGetParams)
	if err := c.QueryParser(params); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse VINs",
		})
	}

	statuses, err := v.vehicleOnboardService.GetMintStatusForVins(c.Context(), params.Vins)
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to get mint status for VINs")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(StatusForVinsResponse{
		Statuses: statuses,
	})
}

// FinalizeOnboarding godoc
// @Summary     Finalize onboarding
// @Description Finalizes onboarding process, returns minted token IDs
// @Tags        onboarding,mint
// @Accept      json
// @Produce     json
// @Param       payload body controllers.VinsGetParams true "VINs to finalize"
// @Security    BearerAuth
// @Success     200 {object} controllers.FinalizeResponse
// @Failure     400 {object} fiber.Error "Bad Request"
// @Failure     401 {object} fiber.Error "Unauthorized"
// @Failure     500 {object} fiber.Error "Internal server error"
// @Router      /v1/vehicle/finalize [post]
func (v *VehicleController) FinalizeOnboarding(c *fiber.Ctx) error {
	walletAddress := c.Locals("wallet").(common.Address)

	params := new(VinsGetParams)
	if err := c.BodyParser(params); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse VINs",
		})
	}

	vehicles, err := v.vehicleOnboardService.FinalizeOnboarding(c.Context(), params.Vins, walletAddress)
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to finalize onboarding")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(FinalizeResponse{
		Vehicles: vehicles,
	})
}
