package config

import (
	"github.com/DIMO-Network/shared/pkg/db"
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
	JwtKeySetURL                string      `yaml:"JWT_KEY_SET_URL"`
	TeslaClientID               string      `yaml:"TESLA_CLIENT_ID"`
	TeslaAuthURL                string      `yaml:"TESLA_AUTH_URL"`
	TeslaRedirectURL            string      `yaml:"TESLA_REDIRECT_URL"`
}
