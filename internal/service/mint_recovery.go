package service

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/DIMO-Network/go-transactions"
	registry "github.com/DIMO-Network/go-transactions/contracts"
	"github.com/DIMO-Network/shared/pkg/logfields"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/DIMO-Network/tesla-oracle/pkg/wallet"
	"github.com/aarondl/null/v8"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/rs/zerolog"
)

// Statuses a mint job leaves a record in while it works (duplicated from the
// onboarding package, like the ones above). The job connects (40-43), then marks
// the record MintPending right before it sends the mint's user operation, and
// MintUnknown if the user operation was sent but its receipt was lost.
const (
	OnboardingStatusConnectUnknown = 40
	OnboardingStatusConnectSuccess = 43
	OnboardingStatusMintUnknown    = 50
	OnboardingStatusMintPending    = 51
)

// isMintInFlight reports whether the status is one a mint job leaves a record in
// before the mint is recorded as succeeded or failed.
func isMintInFlight(status int) bool {
	return status >= OnboardingStatusConnectUnknown && status <= OnboardingStatusMintPending && !isFailure(status)
}

// IsMintSent reports whether a mint job sent the record's mint without recording
// how it went: the mint may be on chain.
func IsMintSent(status int) bool {
	return status == OnboardingStatusMintUnknown || status == OnboardingStatusMintPending
}

// MintJobTimeout is how long River lets a mint job run before cancelling it.
const MintJobTimeout = 30 * time.Minute

// mintJobDeadAfter is how long after it started a mint job still marked running is
// taken for dead. A killed pod leaves its job running until River's rescuer
// discards it an hour on, with no error handler and no log. A live job can't run
// this long: it sends nothing once past MintJobTimeout, and a mint it sent before
// then ends within go-zerodev's receipt polling (24 polls 10s apart).
const mintJobDeadAfter = MintJobTimeout + 5*time.Minute

// MintJobs is the part of the River client mint recovery uses.
type MintJobs interface {
	JobList(ctx context.Context, params *river.JobListParams) (*river.JobListResult, error)
}

// mintJobLive reports whether a mint job for the VIN is queued or still working.
func mintJobLive(ctx context.Context, jobs MintJobs, vin string) (bool, error) {
	list, err := jobs.JobList(ctx, river.NewJobListParams().
		Kinds(OnboardingArgs{}.Kind()).
		States(rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable, rivertype.JobStateRunning, rivertype.JobStateScheduled).
		Where("args->>'vin' = @vin", river.NamedArgs{"vin": vin}).
		First(100))
	if err != nil {
		return false, fmt.Errorf("failed to list mint jobs for VIN %s: %w", vin, err)
	}
	for _, job := range list.Jobs {
		if job.State != rivertype.JobStateRunning || job.AttemptedAt == nil || time.Since(*job.AttemptedAt) < mintJobDeadAfter {
			return true, nil
		}
	}
	return false, nil
}

// ChainMint is a vehicle and SD minted on chain.
type ChainMint struct {
	VehicleTokenID   int64
	SyntheticTokenID int64
}

// MintLookup finds a mint on chain by its SD's address. The registry mints an SD
// address only once (DeviceAlreadyRegistered), so the address names one mint.
type MintLookup interface {
	MintBySDAddress(ctx context.Context, sdAddress common.Address) (*ChainMint, error)
}

type registryMintLookup struct {
	chain                    ethereum.ContractCaller
	registry                 *registry.Registry
	registryAddress          common.Address
	vehicleIDAddress         common.Address
	syntheticDeviceIDAddress common.Address
}

// NewRegistryMintLookup reads mints from the DIMO registry the transactions client
// mints through, over the client's RPC connection.
func NewRegistryMintLookup(tr *transactions.Client) MintLookup {
	return &registryMintLookup{
		chain:                    ethclient.NewClient(tr.ZerodevClient.RpcClients.Network),
		registry:                 tr.Registry,
		registryAddress:          tr.RegistryAddress,
		vehicleIDAddress:         tr.VehicleIdAddress,
		syntheticDeviceIDAddress: tr.SyntheticDeviceIdAddress,
	}
}

// MintBySDAddress returns the SD minted with the address and the vehicle it's
// paired with, or nil if no SD has the address.
func (l *registryMintLookup) MintBySDAddress(ctx context.Context, sdAddress common.Address) (*ChainMint, error) {
	out, err := l.call(ctx, l.registry.PackGetSyntheticDeviceIdByAddress(sdAddress))
	if err != nil {
		return nil, fmt.Errorf("failed to look up the SD with address %s: %w", sdAddress.Hex(), err)
	}
	sdTokenID, err := l.registry.UnpackGetSyntheticDeviceIdByAddress(out)
	if err != nil {
		return nil, fmt.Errorf("failed to read the SD with address %s: %w", sdAddress.Hex(), err)
	}
	if sdTokenID.Sign() == 0 {
		return nil, nil
	}

	out, err = l.call(ctx, l.registry.PackGetNodeLink(l.syntheticDeviceIDAddress, l.vehicleIDAddress, sdTokenID))
	if err != nil {
		return nil, fmt.Errorf("failed to look up the vehicle of SD %s: %w", sdTokenID, err)
	}
	vehicleTokenID, err := l.registry.UnpackGetNodeLink(out)
	if err != nil {
		return nil, fmt.Errorf("failed to read the vehicle of SD %s: %w", sdTokenID, err)
	}
	if vehicleTokenID.Sign() == 0 {
		return nil, fmt.Errorf("SD %s with address %s is paired with no vehicle", sdTokenID, sdAddress.Hex())
	}

	return &ChainMint{VehicleTokenID: vehicleTokenID.Int64(), SyntheticTokenID: sdTokenID.Int64()}, nil
}

func (l *registryMintLookup) call(ctx context.Context, data []byte) ([]byte, error) {
	return l.chain.CallContract(ctx, ethereum.CallMsg{To: &l.registryAddress, Data: data}, (*big.Int)(nil))
}

// RecordChainMint looks up the mint of the SD address on chain and, if it's there,
// records it on the record: its vehicle and SD, and MintSuccess. It reports whether
// it found the mint. The caller saves the record.
func RecordChainMint(ctx context.Context, lookup MintLookup, record *dbmodels.Onboarding, sdAddress common.Address) (bool, error) {
	mint, err := lookup.MintBySDAddress(ctx, sdAddress)
	if err != nil || mint == nil {
		return false, err
	}
	if record.VehicleTokenID.Valid && record.VehicleTokenID.Int64 != mint.VehicleTokenID {
		return false, fmt.Errorf("SD address %s was minted for vehicle %d, not the record's vehicle %d", sdAddress.Hex(), mint.VehicleTokenID, record.VehicleTokenID.Int64)
	}

	record.VehicleTokenID = null.Int64From(mint.VehicleTokenID)
	record.SyntheticTokenID = null.Int64From(mint.SyntheticTokenID)
	record.OnboardingStatus = OnboardingStatusMintSuccess
	return true, nil
}

// MintRecovery settles the records of mint jobs that died: a killed pod leaves its
// record in flight, and River's rescuer discards the job without a word.
type MintRecovery struct {
	logger     *zerolog.Logger
	lookup     MintLookup
	wallets    wallet.SDWalletsAPI
	onboarding repository.OnboardingRepository
}

func NewMintRecovery(logger *zerolog.Logger, lookup MintLookup, wallets wallet.SDWalletsAPI, onboarding repository.OnboardingRepository) *MintRecovery {
	return &MintRecovery{logger: logger, lookup: lookup, wallets: wallets, onboarding: onboarding}
}

// RecoverAll recovers every record a mint job left in flight.
func (r *MintRecovery) RecoverAll(ctx context.Context, jobs MintJobs) error {
	records, err := r.onboarding.GetOnboardingsByStatusRange(ctx, OnboardingStatusConnectUnknown, OnboardingStatusMintPending)
	if err != nil {
		return fmt.Errorf("failed to load records with mints in flight: %w", err)
	}
	for _, record := range records {
		if err := r.Recover(ctx, jobs, record); err != nil {
			r.logger.Error().Err(err).Str(logfields.VIN, record.Vin).Msg("Failed to recover a mint.")
		}
	}
	return nil
}

// Recover settles a record its mint job left in flight, once no mint job for the
// VIN is queued or working. A record left before the mint was sent is marked
// failed, so the VIN can be minted again. One left after is checked against the
// chain: a mint there is recorded. With none there, the record is marked failed
// and keeps its SD wallet index, so the next mint sends the same SD address and the
// registry lets at most one of the two land, even if the first lands late.
func (r *MintRecovery) Recover(ctx context.Context, jobs MintJobs, record *dbmodels.Onboarding) error {
	if !isMintInFlight(record.OnboardingStatus) {
		return nil
	}
	if live, err := mintJobLive(ctx, jobs, record.Vin); err != nil || live {
		return err
	}

	status := record.OnboardingStatus
	logger := r.logger.With().Str(logfields.VIN, record.Vin).Int("onboardingStatus", status).Logger()

	if !IsMintSent(status) {
		logger.Error().Msg("Mint job died before sending its mint. Marked the mint failed, so the VIN can be minted again.")
		record.OnboardingStatus = OnboardingStatusMintFailure
		return r.save(ctx, logger, record, status)
	}

	how := "died after sending its mint"
	if status == OnboardingStatusMintUnknown {
		how = "sent its mint but lost the receipt"
	}
	if !record.WalletIndex.Valid {
		logger.Error().Msgf("Mint job %s, with no SD wallet index saved to look the mint up by. Left the record as is.", how)
		return nil
	}

	sdAddress, err := r.wallets.GetAddress(ctx, uint32(record.WalletIndex.Int64))
	if err != nil {
		return fmt.Errorf("failed to get the SD address of wallet index %d: %w", record.WalletIndex.Int64, err)
	}
	logger = logger.With().Int64("walletIndex", record.WalletIndex.Int64).Str("sdAddress", sdAddress.Hex()).Logger()

	minted, err := RecordChainMint(ctx, r.lookup, record, sdAddress)
	if err != nil {
		return err
	}
	if minted {
		logger.Error().Int64(logfields.VehicleTokenID, record.VehicleTokenID.Int64).Int64("syntheticDeviceTokenId", record.SyntheticTokenID.Int64).
			Msgf("Mint job %s, and the mint landed. Recorded the minted vehicle and SD.", how)
	} else {
		logger.Error().Msgf("Mint job %s, and the mint isn't on chain. Marked the mint failed, so the VIN can be minted again with the same SD address.", how)
		record.OnboardingStatus = OnboardingStatusMintFailure
	}
	return r.save(ctx, logger, record, status)
}

// save saves the recovered record unless a job moved it on since it was read.
func (r *MintRecovery) save(ctx context.Context, logger zerolog.Logger, record *dbmodels.Onboarding, readStatus int) error {
	saved, err := r.onboarding.UpdateOnboardingIfStatus(ctx, record, readStatus)
	if err != nil {
		return fmt.Errorf("failed to save the recovered mint of VIN %s: %w", record.Vin, err)
	}
	if !saved {
		logger.Info().Msg("Record changed while its mint was recovered; left it to the job that changed it.")
	}
	return nil
}
