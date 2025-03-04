package config

import (
	"github.com/DIMO-Network/shared/db"
)

type Settings struct {
	LogLevel           string      `yaml:"LOG_LEVEL"`
	Environment        string      `yaml:"ENVIRONMENT"`
	MonPort            int         `yaml:"MON_PORT"`
	GRPCPort           int         `yaml:"GRPC_PORT"`
	ChainID            int         `yaml:"CHAIN_ID"`
	TopicContractEvent string      `yaml:"CONTRACT_EVENT_TOPIC"`
	KafkaBrokers       string      `yaml:"KAFKA_BROKERS"`
	DB                 db.Settings `yaml:"DB"`
}
