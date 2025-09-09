package models

import "fmt"

type GraphQLRequest struct {
	Query string `json:"query"`
}

type Vehicle struct {
	VIN                 string          `json:"vin"`
	ID                  string          `json:"id"`
	TokenID             int64           `json:"tokenId"`
	MintedAt            string          `json:"mintedAt"`
	Owner               string          `json:"owner"`
	Definition          Definition      `json:"definition"`
	SyntheticDevice     SyntheticDevice `json:"syntheticDevice"`
	ConnectionStatus    string          `json:"connectionStatus"`
	DisconnectionStatus string          `json:"disconnectionStatus"`
}

type SyntheticDevice struct {
	ID       string `json:"id"`
	TokenID  int64  `json:"tokenId"`
	MintedAt string `json:"mintedAt"`
	Address  string `json:"address"`
}

type Definition struct {
	ID    string `json:"id"`
	Make  string `json:"make"`
	Model string `json:"model"`
	Year  int    `json:"year"`
}

type SingleVehicle struct {
	Vehicle Vehicle `json:"vehicle"`
}

type SingleVehicleData struct {
	Data SingleVehicle `json:"data"`
}

type PageInfo struct {
	HasPreviousPage bool   `json:"hasPreviousPage"`
	HasNextPage     bool   `json:"hasNextPage"`
	StartCursor     string `json:"startCursor"`
	EndCursor       string `json:"endCursor"`
}

type PagedVehiclesNodes struct {
	Nodes    []Vehicle `json:"nodes"`
	PageInfo PageInfo  `json:"pageInfo"`
}

type PagedVehicles struct {
	VehicleNodes PagedVehiclesNodes `json:"vehicles"`
}

type SingleDeviceDefinition struct {
	DeviceDefinition DeviceDefinition `json:"deviceDefinition"`
}

type DeviceDefinition struct {
	DeviceDefinitionID string       `json:"deviceDefinitionId"`
	Manufacturer       Manufacturer `json:"manufacturer"`
	Model              string       `json:"model"`
	Year               int          `json:"year"`
}

type Manufacturer struct {
	TokenID uint64 `json:"tokenId"`
	Name    string `json:"name"`
}

type GraphQlData[T any] struct {
	Data T `json:"data"`
}

type StatusDecision struct {
	Action  string      `json:"action"`
	Message string      `json:"message"`
	Next    *NextAction `json:"next,omitempty"`
}

type NextAction struct {
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
}

type VehicleStatusResponse struct {
	Action  string      `json:"action"`
	Message string      `json:"message"`
	Next    *NextAction `json:"next"`
}

type TeslaVehicleRes struct {
	ExternalID string              `json:"externalId"`
	VIN        string              `json:"vin"`
	Definition DeviceDefinitionRes `json:"definition"`
}

type DeviceDefinitionRes struct {
	Make               string `json:"make"`
	Model              string `json:"model"`
	Year               int    `json:"year"`
	DeviceDefinitionID string `json:"id"`
}

type VirtualKeyStatus int

const (
	Incapable VirtualKeyStatus = iota
	Paired
	Unpaired
)

type VirtualKeyStatusResponse struct {
	Added  bool             `json:"added"`
	Status VirtualKeyStatus `json:"status" swaggertype:"string"`
}

func (s VirtualKeyStatus) String() string {
	switch s {
	case Incapable:
		return "Incapable"
	case Paired:
		return "Paired"
	case Unpaired:
		return "Unpaired"
	}
	return ""
}

func (s VirtualKeyStatus) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s *VirtualKeyStatus) UnmarshalText(text []byte) error {
	switch str := string(text); str {
	case "Incapable":
		*s = Incapable
	case "Paired":
		*s = Paired
	case "Unpaired":
		*s = Unpaired
	default:
		return fmt.Errorf("unrecognized status %q", str)
	}
	return nil
}

// SubmitCommandResponse represents the response from submitting a Tesla command
type SubmitCommandResponse struct {
	CommandID string `json:"commandId"`
	Status    string `json:"status"`
	Message   string `json:"message"`
}
