package config

import (
	"github.com/DIMO-Network/shared/db"
)

type Settings struct {
	Environment        string      `yaml:"ENVIRONMENT"`
	Port               int         `yaml:"PORT"`
	MonPort            int         `yaml:"MON_PORT"`
	LogLevel           string      `yaml:"LOG_LEVEL"`
	ChainID            int         `yaml:"CHAIN_ID"`
	TopicContractEvent string      `yaml:"CONTRACT_EVENT_TOPIC"`
	KafkaBrokers       string      `yaml:"KAFKA_BROKERS"`
	DB                 db.Settings `yaml:"DB"`
}
