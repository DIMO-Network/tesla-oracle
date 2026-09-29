package onboarding

import (
	"context"
	"math/big"
	"testing"

	"github.com/DIMO-Network/go-transactions"
	registry "github.com/DIMO-Network/go-transactions/contracts"
	"github.com/DIMO-Network/go-zerodev"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/test"
	mods "github.com/DIMO-Network/tesla-oracle/internal/models"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/DIMO-Network/tesla-oracle/pkg/wallet"
	"github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/ethereum/go-ethereum/common"
	signer "github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/riverqueue/river"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// lostReceiptTransactor behaves like the transactions client when go-zerodev
// sends the user operation but its receipt poll fails: no error, no result. The
// mint is on chain, but nothing says which token IDs it produced.
type lostReceiptTransactor struct{ calls int }

func (l *lostReceiptTransactor) GetMintVehicleAndSDTypedDataV2(*big.Int) *signer.TypedData {
	return testTypedData()
}

func (l *lostReceiptTransactor) GetMintSDTypedDataV2(*big.Int, *big.Int) *signer.TypedData {
	return testTypedData()
}

func (l *lostReceiptTransactor) MintVehicleAndSDWithDD(*registry.MintVehicleAndSdWithDdInput, bool, bool) (*zerodev.UserOperationResult, *transactions.MintVehicleAndSDWithDDResult, error) {
	l.calls++
	return &zerodev.UserOperationResult{}, nil, nil
}

func (l *lostReceiptTransactor) MintVehicleAndSDWithDDAndSACD(*registry.MintVehicleAndSdWithDdInput, registry.SacdInput, bool, bool) (*zerodev.UserOperationResult, *transactions.MintVehicleAndSDWithDDResult, error) {
	l.calls++
	return &zerodev.UserOperationResult{}, nil, nil
}

func (l *lostReceiptTransactor) MintSD(*registry.MintSyntheticDeviceInput, bool, bool) (*zerodev.UserOperationResult, *transactions.MintSDResult, error) {
	l.calls++
	return &zerodev.UserOperationResult{}, nil, nil
}

func testTypedData() *signer.TypedData {
	return &signer.TypedData{
		Types: signer.Types{
			"EIP712Domain": {{Name: "name", Type: "string"}},
			"Mint":         {{Name: "node", Type: "uint256"}},
		},
		PrimaryType: "Mint",
		Domain:      signer.TypedDataDomain{Name: "test"},
		Message:     signer.TypedDataMessage{"node": "1"},
	}
}

// TestMintWithLostResult: the mint landed but its result didn't come back. The
// worker used to dereference the nil result and panic, River retried (with 25
// attempts), and the retry minted again. Now the job fails once, and the record
// is parked at MintUnknown, which is never resubmitted, with the SD wallet index
// saved so the minted SD can be found by its address.
func TestMintWithLostResult(t *testing.T) {
	ctx := context.Background()
	pdb, container, settings := test.StartContainerDatabase(ctx, t, "../../migrations")
	settings.ConnectionTokenID = "1"
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	logger := zerolog.Nop()
	identity := new(test.MockIdentityAPIService)
	identity.On("FetchDeviceDefinitionByID", "tesla_model-y_2025").Return(&mods.DeviceDefinition{
		DeviceDefinitionID: "tesla_model-y_2025",
		Manufacturer:       mods.Manufacturer{TokenID: 1, Name: "Tesla"},
		Model:              "Model Y",
		Year:               2025,
	}, nil)

	testCases := []struct {
		name           string
		vin            string
		vehicleTokenID null.Int64
		sacd           *OnboardingSacd
	}{
		{name: "vehicle and SD", vin: "XP7YHCER3SB000001"},
		{name: "vehicle and SD with SACD", vin: "XP7YHCER3SB000002", sacd: &OnboardingSacd{
			Grantee: common.HexToAddress("0x0000000000000000000000000000000000000abc"), Permissions: big.NewInt(1), Expiration: big.NewInt(1),
		}},
		{name: "SD only (reconnect)", vin: "XP7YHCER3SB000003", vehicleTokenID: null.Int64From(189017)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			record := dbmodels.Onboarding{
				Vin:                tc.vin,
				VehicleTokenID:     tc.vehicleTokenID,
				OnboardingStatus:   23, // OnboardingStatusVendorValidationSuccess
				DeviceDefinitionID: null.StringFrom("tesla_model-y_2025"),
			}
			require.NoError(t, record.Insert(ctx, pdb.DBS().Writer, boil.Infer()))

			tr := &lostReceiptTransactor{}
			w := &OnboardingWorker{
				settings: &settings,
				logger:   logger,
				identity: identity,
				dbs:      &pdb,
				tr:       tr,
				ws:       wallet.NewSDWalletsService(logger, "cabaabd8c7c7d27347349e48fb11319bc6656cb6cc1bdc717e94dae8db7e6bc2"),
			}

			var err error
			require.NotPanics(t, func() {
				err = w.Work(ctx, &river.Job[OnboardingArgs]{Args: OnboardingArgs{
					VIN:       tc.vin,
					Owner:     common.HexToAddress("0x0000000000000000000000000000000000000def"),
					Signature: []byte{1},
					Sacd:      tc.sacd,
				}})
			})
			require.Error(t, err)
			require.Equal(t, 1, tr.calls, "work error: %v", err)

			saved, err := dbmodels.FindOnboarding(ctx, pdb.DBS().Reader, tc.vin)
			require.NoError(t, err)
			require.Equal(t, OnboardingStatusMintUnknown, saved.OnboardingStatus)
			require.True(t, saved.WalletIndex.Valid, "SD wallet index must be saved to find the minted SD")
			require.False(t, saved.SyntheticTokenID.Valid)
		})
	}
}
