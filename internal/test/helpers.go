package test

import (
	"os"

	"github.com/rs/zerolog"
)

func Logger() *zerolog.Logger {
	l := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "devices-api").
		Logger()
	return &l
}
