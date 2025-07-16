package controllers

import (
	//"bytes"
	//"fmt"
	//"io"
	//"net/http"

	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

type TeslaController struct {
	settings *config.Settings
	logger   *zerolog.Logger
}

func NewTeslaController(settings *config.Settings, logger *zerolog.Logger) *TeslaController {
	return &TeslaController{
		settings: settings,
		logger:   logger,
	}
}

// GetSettings
// @Summary Get private app configuration parameters
// @Description Get config params for frontend app
// @Tags Settings
// @Produce json
// @Success 200
// @Security     BearerAuth
// @Router /v1/tesla/settings [get]
func (v *TeslaController) GetSettings(c *fiber.Ctx) error {
	payload := TeslaSettingsResponse{
		TeslaClientID:    v.settings.TeslaClientID,
		TeslaAuthURL:     v.settings.TeslaAuthURL,
		TeslaRedirectURI: v.settings.TeslaRedirectURL,
	}
	return c.JSON(payload)
}

type TeslaSettingsResponse struct {
	TeslaAuthURL     string `json:"authUrl"`
	TeslaClientID    string `json:"clientId"`
	TeslaRedirectURI string `json:"redirectUri"`
}

// ListVehicles
// @Summary Get public app configuration parameters
// @Description Get config params for frontend app
// @Tags Settings
// @Produce json
// @Success 200
// @Router /v1/tesla/vehicles [post]
func (v *TeslaController) ListVehicles(c *fiber.Ctx) error {

	return nil
}

type VehiclesResponse struct {
	ClientID string `json:"clientId"`
}

type CompleteOAuthExchangeResponseWrapper struct {
	Vehicles []TeslaVehicle `json:"vehicles"`
}

type TeslaVehicle struct {
	ExternalID string           `json:"externalId"`
	VIN        string           `json:"vin"`
	Definition DeviceDefinition `json:"definition"`
}

type DeviceDefinition struct {
	Make               string `json:"make"`
	Model              string `json:"model"`
	Year               int    `json:"year"`
	DeviceDefinitionID string `json:"id"`
}
