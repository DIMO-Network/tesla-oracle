package config

import (
	"net/url"

	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/ethereum/go-ethereum/common"
)

type Settings struct {
	Environment                 string      `yaml:"ENVIRONMENT"`
	Port                        int         `yaml:"PORT"`
	GRPCPort                    int         `yaml:"GRPC_PORT"`
	MonPort                     int         `yaml:"MON_PORT"`
	WebPort                     int         `yaml:"WEB_PORT"`
	LogLevel                    string      `yaml:"LOG_LEVEL"`
	ChainID                     int         `yaml:"CHAIN_ID"`
	EnableContractEventConsumer bool        `yaml:"ENABLE_CONTRACT_EVENT_CONSUMER"`
	TopicContractEvent          string      `yaml:"CONTRACT_EVENT_TOPIC"`
	KafkaBrokers                string      `yaml:"KAFKA_BROKERS"`
	DB                          db.Settings `yaml:"DB"`
	ServiceName                 string      `yaml:"SERVICE_NAME"`
	JwtKeySetURL                string      `yaml:"JWT_KEY_SET_URL"`
	UseLocalTLS                 bool        `yaml:"USE_LOCAL_TLS"`

	IdentityAPIEndpoint          url.URL `yaml:"IDENTITY_API_ENDPOINT"`
	DeviceDefinitionsAPIEndpoint url.URL `yaml:"DEVICE_DEFINITIONS_API_ENDPOINT"`

	DimoAuthURL        url.URL        `yaml:"DIMO_AUTH_URL"`
	DimoAuthClientID   common.Address `yaml:"DIMO_AUTH_CLIENT_ID"`
	DimoAuthDomain     url.URL        `yaml:"DIMO_AUTH_DOMAIN"`
	DimoAuthPrivateKey string         `yaml:"DIMO_AUTH_PRIVATE_KEY"`

	TeslaClientID               string `yaml:"TESLA_CLIENT_ID"`
	TeslaClientSecret           string `yaml:"TESLA_CLIENT_SECRET"`
	TeslaAuthURL                string `yaml:"TESLA_AUTH_URL"`
	TeslaRedirectURL            string `yaml:"TESLA_REDIRECT_URL"`
	TeslaTokenURL               string `yaml:"TESLA_TOKEN_URL"`
	TeslaFleetURL               string `yaml:"TESLA_FLEET_URL"`
	TeslaTelemetryHostName      string `yaml:"TESLA_TELEMETRY_HOST_NAME"`
	TeslaTelemetryPort          int    `yaml:"TESLA_TELEMETRY_PORT"`
	TeslaTelemetryCACertificate string `yaml:"TESLA_TELEMETRY_CA_CERTIFICATE"`
	TeslaRequiredScopes         string `yaml:"TESLA_REQUIRED_SCOPES"`
}
