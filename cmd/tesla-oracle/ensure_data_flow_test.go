package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseVehicleTokenIDArg(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		tokenID, err := parseVehicleTokenIDArg([]string{"tesla-oracle", "ensure-data-flow", "123"})
		require.NoError(t, err)
		require.Equal(t, int64(123), tokenID)
	})

	t.Run("missing arg", func(t *testing.T) {
		_, err := parseVehicleTokenIDArg([]string{"tesla-oracle", "ensure-data-flow"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "usage: ensure-data-flow")
	})

	t.Run("invalid arg", func(t *testing.T) {
		_, err := parseVehicleTokenIDArg([]string{"tesla-oracle", "ensure-data-flow", "abc"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid vehicle token id")
	})
}
