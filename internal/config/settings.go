package config

import (
	"github.com/DIMO-Network/shared/db"
)

type Settings struct {
	Environment string      `yaml:"ENVIRONMENT"`
	Port        int         `yaml:"PORT"`
	MonPort     int         `yaml:"MON_PORT"`
	LogLevel    string      `yaml:"LOG_LEVEL"`
	ChainID     int         `yaml:"CHAIN_ID"`
	DB          db.Settings `yaml:"DB"`
}
