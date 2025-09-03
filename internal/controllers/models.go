package controllers

import (
	"github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
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

type VinsVerifyParams struct {
	Vins []service.VinWithTokenID `json:"vins" query:"vins"`
}

type StatusForVinsResponse struct {
	Statuses []service.VinStatus `json:"statuses"`
}

type VinsGetParams struct {
	Vins []string `json:"vins" query:"vins"`
}

type MintDataForVins struct {
	VinMintingData []service.VinTransactionData `json:"vinMintingData"`
}

type FinalizeResponse struct {
	Vehicles []service.OnboardedVehicle `json:"vehicles"`
}
