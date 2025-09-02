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

//type TeslaVehicle struct {
//	ExternalID string           `json:"externalId"`
//	VIN        string           `json:"vin"`
//	Definition DeviceDefinition `json:"definition"`
//}

type VinInput struct {
	VIN string `json:"vin"`
}

//type DeviceDefinition struct {
//	Make               string `json:"make"`
//	Model              string `json:"model"`
//	Year               int    `json:"year"`
//	DeviceDefinitionID string `json:"id"`
//}

//type VirtualKeyStatus int
//
//const (
//	Incapable VirtualKeyStatus = iota
//	Paired
//	Unpaired
//)
//
//type VirtualKeyStatusResponse struct {
//	Added  bool             `json:"added"`
//	Status VirtualKeyStatus `json:"status" swaggertype:"string"`
//}
//
//func (s VirtualKeyStatus) String() string {
//	switch s {
//	case Incapable:
//		return "Incapable"
//	case Paired:
//		return "Paired"
//	case Unpaired:
//		return "Unpaired"
//	}
//	return ""
//}
//
//func (s VirtualKeyStatus) MarshalText() ([]byte, error) {
//	return []byte(s.String()), nil
//}
//
//func (s *VirtualKeyStatus) UnmarshalText(text []byte) error {
//	switch str := string(text); str {
//	case "Incapable":
//		*s = Incapable
//	case "Paired":
//		*s = Paired
//	case "Unpaired":
//		*s = Unpaired
//	default:
//		return fmt.Errorf("unrecognized status %q", str)
//	}
//	return nil
//}
