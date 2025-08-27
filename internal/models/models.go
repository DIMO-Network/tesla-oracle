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

type StatusDecisionAction string

const (
	ActionSetTelemetryConfig StatusDecisionAction = "set_telemetry_config"
	ActionOpenTeslaDeeplink  StatusDecisionAction = "open_tesla_deeplink"
	ActionUpdateFirmware     StatusDecisionAction = "update_firmware"
	ActionStartPolling       StatusDecisionAction = "start_polling"
	ActionPromptToggle       StatusDecisionAction = "prompt_toggle"
	ActionDummy              StatusDecisionAction = "do_nothing"
)

type StatusDecisionResponse struct {
	Action  StatusDecisionAction `json:"action"`
	Message string               `json:"message"`
	Next    *NextAction          `json:"next,omitempty"`
}

type NextAction struct {
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
}
