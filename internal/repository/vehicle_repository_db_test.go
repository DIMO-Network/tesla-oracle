package repository_test

import (
	"context"
	"testing"

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/test"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// TestDeleteSyntheticDeviceWithCommandHistory: a car that was ever sent a command
// has device_command_requests rows pointing at its synthetic_devices row. Deleting
// that row (vehicle burned) used to fail on the foreign key, every time.
func TestDeleteSyntheticDeviceWithCommandHistory(t *testing.T) {
	ctx := context.Background()
	pdb, container, _ := test.StartContainerDatabase(ctx, t, "../../migrations")
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	address := common.HexToAddress("0x00000000000000000000000000000000000000b1")
	device := dbmodels.SyntheticDevice{
		Address:            address.Bytes(),
		Vin:                "XP7YHCER3SB582506",
		VehicleTokenID:     null.IntFrom(189017),
		SubscriptionStatus: null.StringFrom("pending"),
	}
	require.NoError(t, device.Insert(ctx, pdb.DBS().Writer, boil.Infer()))

	command := dbmodels.DeviceCommandRequest{
		ID:             "2mN3cmdksuid",
		VehicleTokenID: 189017,
		Command:        "doors/lock",
		Status:         "completed",
	}
	require.NoError(t, command.Insert(ctx, pdb.DBS().Writer, boil.Infer()))

	logger := zerolog.Nop()
	repo := repository.NewVehicleRepository(&pdb, new(cipher.ROT13Cipher), &logger)
	require.NoError(t, repo.DeleteSyntheticDevice(ctx, address.Bytes()))

	exists, err := dbmodels.DeviceCommandRequestExists(ctx, pdb.DBS().Reader, command.ID)
	require.NoError(t, err)
	require.False(t, exists, "command history for a deleted device should go with it")
}
