package models

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

const (
	ActionSetTelemetryConfig = "set_telemetry_config"
	ActionOpenTeslaDeeplink  = "open_tesla_deeplink"
	ActionUpdateFirmware     = "update_firmware"
	ActionStartPolling       = "start_polling"
	ActionPromptToggle       = "prompt_toggle"
	ActionDummy              = "do_nothing"
)

const (
	MessageReadyToStartDataFlow    = "Vehicle ready to start data flow. Call start data flow endpoint"
	MessageVirtualKeyNotPaired     = "Virtual key not paired. Open Tesla app deeplink for pairing."
	MessageFirmwareTooOld          = "Firmware too old. Please update to 2025.20 or higher."
	MessageStreamingToggleDisabled = "Streaming toggle disabled. Prompt user to enable it."
)

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
	Message string      `json:"message"`
	Next    *NextAction `json:"next"`
}
