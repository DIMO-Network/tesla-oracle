package onboarding

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DIMO-Network/go-transactions"
	registry "github.com/DIMO-Network/go-transactions/contracts"
	"github.com/DIMO-Network/go-zerodev"
	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/test"
	mods "github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/DIMO-Network/tesla-oracle/pkg/wallet"
	"github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/ethereum/go-ethereum/common"
	signer "github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/friendsofgo/errors"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/riverqueue/river/rivertype"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// fakeChain is the registry as mints and mint lookups see it: an SD address mints
// once, and a second mint of it fails with DeviceAlreadyRegistered.
type fakeChain struct {
	mu    sync.Mutex
	mints map[common.Address]service.ChainMint
}

func newFakeChain() *fakeChain {
	return &fakeChain{mints: map[common.Address]service.ChainMint{}}
}

// lastTokenID numbers the token IDs of every fakeChain, so that no two records
// get the same.
var lastTokenID atomic.Int64

func (c *fakeChain) MintBySDAddress(_ context.Context, sdAddress common.Address) (*service.ChainMint, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if mint, ok := c.mints[sdAddress]; ok {
		return &mint, nil
	}
	return nil, nil
}

// land mints the SD address, for the vehicle if one is given or else with a new one.
func (c *fakeChain) land(sdAddress common.Address, vehicle *big.Int) (service.ChainMint, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.mints[sdAddress]; ok {
		return service.ChainMint{}, fmt.Errorf("DeviceAlreadyRegistered(%s)", sdAddress.Hex())
	}
	tokenID := lastTokenID.Add(1)
	mint := service.ChainMint{VehicleTokenID: 1000 + tokenID, SyntheticTokenID: 500000 + tokenID}
	if vehicle != nil {
		mint.VehicleTokenID = vehicle.Int64()
	}
	c.mints[sdAddress] = mint
	return mint, nil
}

// errKilled stands in for SIGKILL: chainTransactor panics with it as a mint is sent.
var errKilled = errors.New("killed")

// chainTransactor mints on a fakeChain.
type chainTransactor struct {
	chain *fakeChain
	// onSend, if set, runs as each mint is sent, before it reaches the chain.
	onSend func(sdAddress common.Address)
	// kill kills the job as it sends its mint. The mint lands anyway if land is set.
	kill, land bool
	// sent are the SD addresses of the mints sent.
	sent []common.Address
}

func (c *chainTransactor) GetMintVehicleAndSDTypedDataV2(*big.Int) *signer.TypedData {
	return testTypedData()
}

func (c *chainTransactor) GetMintSDTypedDataV2(*big.Int, *big.Int) *signer.TypedData {
	return testTypedData()
}

func (c *chainTransactor) send(sdAddress common.Address, vehicle *big.Int) (service.ChainMint, error) {
	c.sent = append(c.sent, sdAddress)
	if c.onSend != nil {
		c.onSend(sdAddress)
	}
	if c.kill {
		if c.land {
			_, _ = c.chain.land(sdAddress, vehicle)
		}
		panic(errKilled)
	}
	return c.chain.land(sdAddress, vehicle)
}

func (c *chainTransactor) MintVehicleAndSDWithDD(data *registry.MintVehicleAndSdWithDdInput, _ bool, _ bool) (*zerodev.UserOperationResult, *transactions.MintVehicleAndSDWithDDResult, error) {
	mint, err := c.send(data.SyntheticDeviceAddr, nil)
	if err != nil {
		return nil, nil, err
	}
	return &zerodev.UserOperationResult{}, &transactions.MintVehicleAndSDWithDDResult{
		RegistryVehicleNodeMintedWithDeviceDefinition: registry.RegistryVehicleNodeMintedWithDeviceDefinition{VehicleId: big.NewInt(mint.VehicleTokenID)},
		RegistrySyntheticDeviceNodeMinted:             registry.RegistrySyntheticDeviceNodeMinted{SyntheticDeviceNode: big.NewInt(mint.SyntheticTokenID)},
	}, nil
}

func (c *chainTransactor) MintVehicleAndSDWithDDAndSACD(data *registry.MintVehicleAndSdWithDdInput, _ registry.SacdInput, waitForReceipt bool, getResult bool) (*zerodev.UserOperationResult, *transactions.MintVehicleAndSDWithDDResult, error) {
	return c.MintVehicleAndSDWithDD(data, waitForReceipt, getResult)
}

func (c *chainTransactor) MintSD(data *registry.MintSyntheticDeviceInput, _ bool, _ bool) (*zerodev.UserOperationResult, *transactions.MintSDResult, error) {
	mint, err := c.send(data.SyntheticDeviceAddr, data.VehicleNode)
	if err != nil {
		return nil, nil, err
	}
	return &zerodev.UserOperationResult{}, &transactions.MintSDResult{
		RegistrySyntheticDeviceNodeMinted: registry.RegistrySyntheticDeviceNodeMinted{SyntheticDeviceNode: big.NewInt(mint.SyntheticTokenID), VehicleNode: data.VehicleNode},
	}, nil
}

// vehicleNode is the vehicle an SD only mint pairs with, or nil for a vehicle and
// SD mint, which makes its own.
func vehicleNode(vehicleTokenID null.Int64) *big.Int {
	if !vehicleTokenID.Valid {
		return nil
	}
	return big.NewInt(vehicleTokenID.Int64)
}

// riverJobs is River's job list as mint recovery sees it.
type riverJobs []*rivertype.JobRow

func (j riverJobs) JobList(context.Context, *river.JobListParams) (*river.JobListResult, error) {
	return &river.JobListResult{Jobs: j}, nil
}

// runningJob is a mint job started the given time ago and still marked running.
// One a killed pod left stays so until River's rescuer discards it, an hour on.
func runningJob(startedAgo time.Duration) riverJobs {
	attemptedAt := time.Now().Add(-startedAgo)
	return riverJobs{{Kind: OnboardingArgs{}.Kind(), State: rivertype.JobStateRunning, AttemptedAt: &attemptedAt}}
}

type killTest struct {
	t        *testing.T
	ctx      context.Context
	pdb      db.Store
	settings config.Settings
	identity *test.MockIdentityAPIService
	ws       wallet.SDWalletsAPI
	logs     *bytes.Buffer
}

func newKillTest(t *testing.T) *killTest {
	ctx := context.Background()
	pdb, container, settings := test.StartContainerDatabase(ctx, t, "../../migrations")
	settings.ConnectionTokenID = "1"
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	identity := new(test.MockIdentityAPIService)
	identity.On("FetchDeviceDefinitionByID", "tesla_model-y_2025").Return(&mods.DeviceDefinition{
		DeviceDefinitionID: "tesla_model-y_2025",
		Manufacturer:       mods.Manufacturer{TokenID: 1, Name: "Tesla"},
		Model:              "Model Y",
		Year:               2025,
	}, nil)

	return &killTest{
		t: t, ctx: ctx, pdb: pdb, settings: settings, identity: identity, logs: new(bytes.Buffer),
		ws: wallet.NewSDWalletsService(zerolog.Nop(), "cabaabd8c7c7d27347349e48fb11319bc6656cb6cc1bdc717e94dae8db7e6bc2"),
	}
}

// recoveryOn is the test's mint recovery reading the chain.
// in is the test for the subtest t.
func (k *killTest) in(t *testing.T) *killTest {
	sub := *k
	sub.t = t
	return &sub
}

func (k *killTest) recoveryOn(chain *fakeChain) *service.MintRecovery {
	logger := zerolog.New(k.logs)
	return service.NewMintRecovery(&logger, chain, k.ws, repository.NewOnboardingRepository(&k.pdb, &logger))
}

func (k *killTest) worker(tr mintTransactor, chain *fakeChain) *OnboardingWorker {
	return &OnboardingWorker{
		settings: &k.settings,
		logger:   zerolog.Nop(),
		identity: k.identity,
		dbs:      &k.pdb,
		tr:       tr,
		chain:    chain,
		ws:       k.ws,
	}
}

func (k *killTest) insert(vin string, vehicleTokenID null.Int64) OnboardingArgs {
	record := dbmodels.Onboarding{
		Vin:                vin,
		VehicleTokenID:     vehicleTokenID,
		OnboardingStatus:   OnboardingStatusVendorValidationSuccess,
		DeviceDefinitionID: null.StringFrom("tesla_model-y_2025"),
	}
	require.NoError(k.t, record.Insert(k.ctx, k.pdb.DBS().Writer, boil.Infer()))
	return OnboardingArgs{
		VIN:       vin,
		Owner:     common.HexToAddress("0x0000000000000000000000000000000000000def"),
		Signature: []byte{1},
	}
}

func (k *killTest) record(vin string) *dbmodels.Onboarding {
	record, err := dbmodels.FindOnboarding(k.ctx, k.pdb.DBS().Reader, vin)
	require.NoError(k.t, err)
	return record
}

func (k *killTest) restore(record *dbmodels.Onboarding) {
	_, err := record.Update(k.ctx, k.pdb.DBS().Writer, boil.Infer())
	require.NoError(k.t, err)
}

func (k *killTest) work(w *OnboardingWorker, args OnboardingArgs) error {
	return w.Work(k.ctx, &river.Job[OnboardingArgs]{Args: args})
}

// killAtSend runs a mint job killed as it sends its mint, which lands if lands is
// set, and returns the record as the kill left it: as it was when the mint was
// sent, since a killed pod writes nothing after.
func (k *killTest) killAtSend(args OnboardingArgs, chain *fakeChain, lands bool) (*dbmodels.Onboarding, common.Address) {
	var atSend *dbmodels.Onboarding
	tr := &chainTransactor{chain: chain, kill: true, land: lands, onSend: func(common.Address) {
		atSend = k.record(args.VIN)
	}}
	require.PanicsWithValue(k.t, errKilled, func() { _ = k.work(k.worker(tr, chain), args) })
	require.Len(k.t, tr.sent, 1)
	k.restore(atSend)
	return atSend, tr.sent[0]
}

// requireMintedOnce checks the record has the one mint on chain for its SD address.
func (k *killTest) requireMintedOnce(vin string, chain *fakeChain, sdAddress common.Address) {
	record := k.record(vin)
	require.Equal(k.t, OnboardingStatusMintSuccess, record.OnboardingStatus)
	require.Len(k.t, chain.mints, 1, "one vehicle and SD minted")
	mint := chain.mints[sdAddress]
	require.Equal(k.t, mint.VehicleTokenID, record.VehicleTokenID.Int64)
	require.Equal(k.t, mint.SyntheticTokenID, record.SyntheticTokenID.Int64)
	address, err := k.ws.GetAddress(k.ctx, uint32(record.WalletIndex.Int64))
	require.NoError(k.t, err)
	require.Equal(k.t, sdAddress, address, "the record's wallet index is the minted SD's")
}

// TestMintKilledBeforeSending: a pod killed while its mint job waited for the mint
// lock left the record at ConnectSuccess, which looked like a mint in progress
// forever. Nothing was sent, and the record now says so: no SD wallet index, no
// MintPending. Recovery marks it failed once the job is dead, and the VIN mints.
func TestMintKilledBeforeSending(t *testing.T) {
	k := newKillTest(t)
	args := k.insert("XP7YHCER3SB000101", null.Int64{})
	chain := newFakeChain()

	// The job connects, then waits for the lock another mint holds; the pod is
	// killed then. The job sends nothing once it gets the lock, and it's put back.
	w := k.worker(&chainTransactor{chain: chain, kill: true}, chain)
	w.m.Lock()
	done := make(chan any)
	go func() {
		defer func() { done <- recover() }()
		_ = k.work(w, args)
	}()
	require.Eventually(t, func() bool {
		return k.record(args.VIN).OnboardingStatus == OnboardingStatusConnectSuccess
	}, 5*time.Second, 10*time.Millisecond)
	killed := k.record(args.VIN)
	w.m.Unlock()
	require.Equal(t, errKilled, <-done)
	k.restore(killed)
	require.False(t, killed.WalletIndex.Valid, "a job waiting for the lock has no SD wallet index")

	recovery := k.recoveryOn(chain)
	require.NoError(t, recovery.Recover(k.ctx, runningJob(time.Minute), killed))
	require.Equal(t, OnboardingStatusConnectSuccess, k.record(args.VIN).OnboardingStatus, "a live job's mint is left alone")

	require.NoError(t, recovery.Recover(k.ctx, runningJob(40*time.Minute), killed))
	require.Equal(t, OnboardingStatusMintFailure, k.record(args.VIN).OnboardingStatus, "the VIN can be minted again")
	require.Contains(t, k.logs.String(), "Mint job died before sending its mint")
	require.Contains(t, k.logs.String(), args.VIN)

	tr := &chainTransactor{chain: chain}
	require.NoError(t, k.work(k.worker(tr, chain), args))
	require.Len(t, tr.sent, 1)
	k.requireMintedOnce(args.VIN, chain, tr.sent[0])
}

// TestMintKilledAfterSending: a pod killed after its mint job sent the mint's user
// operation. The record says so, MintPending with the SD wallet index, so recovery
// looks the mint up on chain by the SD's address: it records a mint that landed,
// and lets the VIN mint again if none did. A mint of the VIN sends the same SD
// address every time, and the registry mints an address once, so the VIN never
// mints twice, even when the killed job's mint lands late.
func TestMintKilledAfterSending(t *testing.T) {
	parent := newKillTest(t)

	kinds := []struct {
		name   string
		sdOnly bool
	}{
		{name: "vehicle and SD"},
		{name: "SD only (reconnect)", sdOnly: true},
	}

	records := 0
	for _, kind := range kinds {
		// newRecord inserts a record ready to mint, with a vehicle for an SD only mint.
		newRecord := func(k *killTest) (OnboardingArgs, null.Int64) {
			records++
			var vehicleTokenID null.Int64
			if kind.sdOnly {
				vehicleTokenID = null.Int64From(int64(189000 + records))
			}
			return k.insert(fmt.Sprintf("XP7YHCER3SB%06d", 200+records), vehicleTokenID), vehicleTokenID
		}

		t.Run(kind.name+": the mint landed", func(t *testing.T) {
			k := parent.in(t)
			args, _ := newRecord(k)
			chain := newFakeChain()
			killed, sdAddress := k.killAtSend(args, chain, true)

			require.Equal(t, OnboardingStatusMintPending, killed.OnboardingStatus, "marked sent before sending")
			require.True(t, killed.WalletIndex.Valid, "SD wallet index saved before sending")
			address, err := k.ws.GetAddress(k.ctx, uint32(killed.WalletIndex.Int64))
			require.NoError(t, err)
			require.Equal(t, sdAddress, address, "the saved wallet index is the sent SD's")

			require.NoError(t, k.recoveryOn(chain).Recover(k.ctx, runningJob(40*time.Minute), killed))
			k.requireMintedOnce(args.VIN, chain, sdAddress)
			require.Contains(t, k.logs.String(), "Mint job died after sending its mint, and the mint landed")

			// Finalizing needs nothing more; a job submitted anyway sends nothing.
			tr := &chainTransactor{chain: chain}
			require.NoError(t, k.work(k.worker(tr, chain), args))
			require.Empty(t, tr.sent)
			k.requireMintedOnce(args.VIN, chain, sdAddress)
		})

		t.Run(kind.name+": the mint landed, and the next job finds it", func(t *testing.T) {
			k := parent.in(t)
			args, _ := newRecord(k)
			chain := newFakeChain()
			_, sdAddress := k.killAtSend(args, chain, true)

			tr := &chainTransactor{chain: chain}
			require.NoError(t, k.work(k.worker(tr, chain), args))
			require.Empty(t, tr.sent, "the mint on chain is recorded, not sent again")
			k.requireMintedOnce(args.VIN, chain, sdAddress)
		})

		t.Run(kind.name+": the mint didn't land", func(t *testing.T) {
			k := parent.in(t)
			args, _ := newRecord(k)
			chain := newFakeChain()
			killed, sdAddress := k.killAtSend(args, chain, false)

			recovery := k.recoveryOn(chain)
			require.NoError(t, recovery.Recover(k.ctx, runningJob(time.Minute), killed))
			require.Equal(t, OnboardingStatusMintPending, k.record(args.VIN).OnboardingStatus, "a live job's mint is left alone")

			require.NoError(t, recovery.Recover(k.ctx, runningJob(40*time.Minute), killed))
			recovered := k.record(args.VIN)
			require.Equal(t, OnboardingStatusMintFailure, recovered.OnboardingStatus, "the VIN can be minted again")
			require.Equal(t, killed.WalletIndex, recovered.WalletIndex, "with the same SD wallet index")
			require.Contains(t, k.logs.String(), "Mint job died after sending its mint, and the mint isn't on chain")

			tr := &chainTransactor{chain: chain}
			require.NoError(t, k.work(k.worker(tr, chain), args))
			require.Equal(t, []common.Address{sdAddress}, tr.sent, "the next mint sends the same SD address")
			k.requireMintedOnce(args.VIN, chain, sdAddress)
		})

		t.Run(kind.name+": the mint lands after recovery", func(t *testing.T) {
			k := parent.in(t)
			args, vehicleTokenID := newRecord(k)
			chain := newFakeChain()
			killed, sdAddress := k.killAtSend(args, chain, false)
			require.NoError(t, k.recoveryOn(chain).Recover(k.ctx, runningJob(40*time.Minute), killed))
			require.Equal(t, OnboardingStatusMintFailure, k.record(args.VIN).OnboardingStatus)

			// The killed job's user operation lands late, before the next mint.
			_, err := chain.land(sdAddress, vehicleNode(vehicleTokenID))
			require.NoError(t, err)

			tr := &chainTransactor{chain: chain}
			require.NoError(t, k.work(k.worker(tr, chain), args))
			require.Empty(t, tr.sent, "the late mint is recorded, not sent again")
			k.requireMintedOnce(args.VIN, chain, sdAddress)
		})

		t.Run(kind.name+": the mint lands as the next one is sent", func(t *testing.T) {
			k := parent.in(t)
			args, vehicleTokenID := newRecord(k)
			chain := newFakeChain()
			killed, sdAddress := k.killAtSend(args, chain, false)
			require.NoError(t, k.recoveryOn(chain).Recover(k.ctx, runningJob(40*time.Minute), killed))

			// The killed job's user operation lands between the next job's chain
			// check and its send: the registry rejects the second mint of the address.
			tr := &chainTransactor{chain: chain, onSend: func(sdAddress common.Address) {
				_, err := chain.land(sdAddress, vehicleNode(vehicleTokenID))
				require.NoError(t, err)
			}}
			require.NoError(t, k.work(k.worker(tr, chain), args))
			require.Equal(t, []common.Address{sdAddress}, tr.sent)
			k.requireMintedOnce(args.VIN, chain, sdAddress)
		})
	}
}

// TestMintLostReceiptRecovered: a mint whose receipt was lost is parked at
// MintUnknown, and recovery records it once it's on chain.
func TestMintLostReceiptRecovered(t *testing.T) {
	k := newKillTest(t)
	args := k.insert("XP7YHCER3SB000301", null.Int64{})
	chain := newFakeChain()

	tr := &lostReceiptTransactor{}
	require.ErrorIs(t, k.work(k.worker(tr, chain), args), errMintResultUnknown)
	parked := k.record(args.VIN)
	require.Equal(t, OnboardingStatusMintUnknown, parked.OnboardingStatus)

	sdAddress, err := k.ws.GetAddress(k.ctx, uint32(parked.WalletIndex.Int64))
	require.NoError(t, err)
	_, err = chain.land(sdAddress, nil)
	require.NoError(t, err)

	// The job is done, so no mint job for the VIN is listed.
	require.NoError(t, k.recoveryOn(chain).Recover(k.ctx, riverJobs{}, parked))
	k.requireMintedOnce(args.VIN, chain, sdAddress)
	require.Contains(t, k.logs.String(), "Mint job sent its mint but lost the receipt, and the mint landed")
}

// TestMintRecoveryReadsRiverJobs runs recovery against River's own job table: a
// mint job counts as live while it's queued or running, and as dead once it has
// been running past its timeout, as a job a killed pod left does.
func TestMintRecoveryReadsRiverJobs(t *testing.T) {
	k := newKillTest(t)
	sqlDB := k.pdb.DBS().Writer.DB
	migrator, err := rivermigrate.New(riverdatabasesql.New(sqlDB), &rivermigrate.Config{Schema: "tesla_oracle"})
	require.NoError(t, err)
	_, err = migrator.Migrate(k.ctx, rivermigrate.DirectionUp, nil)
	require.NoError(t, err)
	client, err := river.NewClient(riverdatabasesql.New(sqlDB), &river.Config{})
	require.NoError(t, err)

	args := k.insert("XP7YHCER3SB000401", null.Int64{})
	other := k.insert("XP7YHCER3SB000402", null.Int64{})
	record := k.record(args.VIN)
	record.OnboardingStatus = OnboardingStatusConnectSuccess
	k.restore(record)

	job, err := client.Insert(k.ctx, args, nil)
	require.NoError(t, err)
	_, err = client.Insert(k.ctx, other, nil)
	require.NoError(t, err)

	recovery := k.recoveryOn(newFakeChain())
	require.NoError(t, recovery.Recover(k.ctx, client, record))
	require.Equal(t, OnboardingStatusConnectSuccess, k.record(args.VIN).OnboardingStatus, "a queued job is live")

	setRunning := func(startedAgo time.Duration) {
		_, err := sqlDB.ExecContext(k.ctx, `UPDATE river_job SET state = 'running', attempt = 1, attempted_at = $1 WHERE id = $2`,
			time.Now().Add(-startedAgo), job.Job.ID)
		require.NoError(t, err)
	}

	setRunning(time.Minute)
	require.NoError(t, recovery.Recover(k.ctx, client, record))
	require.Equal(t, OnboardingStatusConnectSuccess, k.record(args.VIN).OnboardingStatus, "a running job is live")

	setRunning(40 * time.Minute)
	require.NoError(t, recovery.Recover(k.ctx, client, record))
	require.Equal(t, OnboardingStatusMintFailure, k.record(args.VIN).OnboardingStatus, "a job running past its timeout is dead")
}
