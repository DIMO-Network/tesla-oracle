package controllers

import (
	"github.com/DIMO-Network/tesla-oracle/internal/models"
)

// CompleteOAuthExchangeRequest request object for completing tesla OAuth
type CompleteOAuthExchangeRequest struct {
	AuthorizationCode string `json:"authorizationCode"`
	RedirectURI       string `json:"redirectUri"`
}

type CompleteOAuthExchangeResponseWrapper struct {
	Vehicles []models.TeslaVehicleRes `json:"vehicles"`
}

type VinInput struct {
	VIN string `json:"vin"`
}
