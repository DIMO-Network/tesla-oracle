package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/DIMO-Network/tesla-oracle/internal/service"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type stubLookup struct {
	calls   int
	devices []service.SyntheticDeviceInfo
	err     error
}

func (s *stubLookup) GetSyntheticDevicesByVIN(ctx context.Context, vin string) ([]service.SyntheticDeviceInfo, error) {
	s.calls++
	return s.devices, s.err
}

func TestVINMapCachesAndRefreshes(t *testing.T) {
	logger := zerolog.Nop()
	lookup := &stubLookup{
		devices: []service.SyntheticDeviceInfo{
			{VehicleTokenID: 11, WalletChildNum: 7, TokenID: 21},
		},
	}

	vm := NewVINMap(lookup, 20*time.Millisecond, &logger)

	first, err := vm.AddOrFetch(context.Background(), "5YJ3E1EA7KF317000")
	require.NoError(t, err)
	require.Len(t, first.synthDevices, 1)
	require.Equal(t, 1, lookup.calls)

	second, err := vm.AddOrFetch(context.Background(), "5YJ3E1EA7KF317000")
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, 1, lookup.calls)

	time.Sleep(25 * time.Millisecond)

	third, err := vm.AddOrFetch(context.Background(), "5YJ3E1EA7KF317000")
	require.NoError(t, err)
	require.Equal(t, 2, lookup.calls)
	require.NotEqual(t, first.lastRefresh, third.lastRefresh)
}
