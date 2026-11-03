package onboarding

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/DIMO-Network/go-transactions"
	registry "github.com/DIMO-Network/go-transactions/contracts"
	"github.com/DIMO-Network/go-zerodev"
	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/shared/pkg/logfields"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/DIMO-Network/tesla-oracle/pkg/wallet"
	"github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/aarondl/sqlboiler/v4/queries"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	signer "github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/friendsofgo/errors"
	"github.com/riverqueue/river"
	"github.com/rs/zerolog"
)

func NewTransactionsClient(settings *config.Settings) (*transactions.Client, error) {
	if settings.RPCURL.String() == "" {
		return nil, errors.New("invalid configuration: missing RPC URL")
	}
	if settings.BundlerURL.String() == "" {
		return nil, errors.New("invalid configuration: missing Bundler URL")
	}
	if len(settings.RegistryAddress.Bytes()) == 0 {
		return nil, errors.New("invalid configuration: missing Registry address")
	}
	if len(settings.VehicleNftAddress.Bytes()) == 0 {
		return nil, errors.New("invalid configuration: missing OnboardingService NFT address")
	}
	if len(settings.SyntheticNftAddress.Bytes()) == 0 {
		return nil, errors.New("invalid configuration: missing Synthetic NFT address")
	}
	if settings.ChainID == 0 {
		return nil, errors.New("invalid configuration: missing ChainID")
	}
	if len(settings.DeveloperAAWalletAddress.Bytes()) == 0 {
		return nil, errors.New("invalid configuration: missing Developer AA wallet address")
	}
	pk, err := crypto.HexToECDSA(settings.DeveloperPK)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load developer private key")
	}

	trConfig := transactions.ClientConfig{
		AccountAddress:           settings.DeveloperAAWalletAddress,
		AccountPK:                pk,
		RpcURL:                   &settings.RPCURL,
		PaymasterURL:             &settings.BundlerURL,
		BundlerURL:               &settings.BundlerURL,
		ChainID:                  big.NewInt(int64(settings.ChainID)),
		RegistryAddress:          settings.RegistryAddress,
		VehicleIdAddress:         settings.VehicleNftAddress,
		SyntheticDeviceIdAddress: settings.SyntheticNftAddress,
	}

	transactionsClient, err := transactions.NewClient(&trConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create transactions client")
	}

	return transactionsClient, nil
}

// OnboardingSacd and OnboardingArgs are the service's types: the service inserts
// the jobs this worker runs, and a second definition here once drifted from it
// (the service's copy lacked InsertOpts, so jobs ran with River's 25 attempts).
type (
	OnboardingSacd = service.OnboardingSacd
	OnboardingArgs = service.OnboardingArgs
)

// mintTransactor is the part of the transactions client the worker uses.
type mintTransactor interface {
	GetMintVehicleAndSDTypedDataV2(connectionID *big.Int) *signer.TypedData
	GetMintSDTypedDataV2(connectionID *big.Int, vehicleNode *big.Int) *signer.TypedData
	MintVehicleAndSDWithDD(data *registry.MintVehicleAndSdWithDdInput, waitForReceipt bool, getResult bool) (*zerodev.UserOperationResult, *transactions.MintVehicleAndSDWithDDResult, error)
	MintVehicleAndSDWithDDAndSACD(data *registry.MintVehicleAndSdWithDdInput, sacdInput registry.SacdInput, waitForReceipt bool, getResult bool) (*zerodev.UserOperationResult, *transactions.MintVehicleAndSDWithDDResult, error)
	MintSD(data *registry.MintSyntheticDeviceInput, waitForReceipt bool, getResult bool) (*zerodev.UserOperationResult, *transactions.MintSDResult, error)
}

type OnboardingWorker struct {
	settings *config.Settings
	logger   zerolog.Logger
	identity service.IdentityAPIService
	dbs      *db.Store
	tr       mintTransactor
	chain    service.MintLookup
	ws       wallet.SDWalletsAPI
	m        sync.RWMutex
	//vendor   VendorOnboardingAPI

	river.WorkerDefaults[OnboardingArgs]
}

func NewOnboardingWorker(settings *config.Settings, logger zerolog.Logger, identity service.IdentityAPIService, dbs *db.Store, tr *transactions.Client, ws wallet.SDWalletsAPI) *OnboardingWorker {
	return &OnboardingWorker{
		settings: settings,
		logger:   logger,
		identity: identity,
		dbs:      dbs,
		tr:       tr,
		chain:    service.NewRegistryMintLookup(tr),
		ws:       ws,
		//vendor:   vendor,
	}
}

func (w *OnboardingWorker) Timeout(*river.Job[OnboardingArgs]) time.Duration {
	return service.MintJobTimeout
}

func (w *OnboardingWorker) Work(ctx context.Context, job *river.Job[OnboardingArgs]) error {
	w.logger.Debug().Str(logfields.VIN, job.Args.VIN).Msg("Minting VIN")

	// Check if the VIN record exists
	record, err := w.GetOnboardingRecord(ctx, job.Args.VIN)
	if err != nil {
		return err
	}

	if record.OnboardingStatus < OnboardingStatusVendorValidationSuccess {
		return fmt.Errorf("insufficient verification status")
	}

	// Check onboarding status, if successful, just return
	if record.OnboardingStatus == OnboardingStatusMintSuccess {
		return nil
	}

	if service.IsMintSent(record.OnboardingStatus) {
		// An earlier job sent this VIN's mint and never recorded how it went. The mint
		// below looks for it on chain before sending anything; connecting first would
		// overwrite the status that says it was sent.
		w.logger.Warn().Str(logfields.VIN, job.Args.VIN).Int("onboardingStatus", record.OnboardingStatus).
			Msg("An earlier mint of this VIN was sent and never recorded; looking for it on chain before minting.")
	} else {
		// Connect to external vendor
		record, err = w.ConnectToVendorAndUpdate(ctx, record, job.Args)
		if err != nil {
			return err
		}
	}

	// If there's no Onboarding record Token ID, mint all
	if !record.VehicleTokenID.Valid {
		w.logger.Debug().Str(logfields.VIN, job.Args.VIN).Msg("No Onboarding record Token ID, minting all")
		record, err = w.MintVehicleWithSDAndUpdate(ctx, record, job.Args)
		if err != nil {
			return err
		}
	}

	// If only SD token ID is missing, mint SD
	if !record.SyntheticTokenID.Valid {
		w.logger.Debug().Str(logfields.VIN, job.Args.VIN).Msg("No Synthetic Device Token ID, minting SD")
		_, err = w.MintSDAndUpdate(ctx, record, job.Args)
		if err != nil {
			return err
		}
	} else {
		// With the token IDs: should the mint's own save have failed, MintSuccess
		// isn't saved without them.
		record.OnboardingStatus = OnboardingStatusMintSuccess
		err = w.update(ctx, record, job.Args, boil.Whitelist(dbmodels.OnboardingColumns.OnboardingStatus, dbmodels.OnboardingColumns.VehicleTokenID, dbmodels.OnboardingColumns.SyntheticTokenID, dbmodels.OnboardingColumns.WalletIndex))
		if err != nil {
			return err
		}
	}

	return nil
}

func (w *OnboardingWorker) GetOnboardingRecord(ctx context.Context, vinToSearch string) (*dbmodels.Onboarding, error) {
	vin, err := dbmodels.Onboardings(dbmodels.OnboardingWhere.Vin.EQ(vinToSearch)).One(ctx, w.dbs.DBS().Reader)

	if err != nil {
		return nil, err
	}

	return vin, nil
}

func (w *OnboardingWorker) MintVehicleWithSDAndUpdate(ctx context.Context, record *dbmodels.Onboarding, args OnboardingArgs) (*dbmodels.Onboarding, error) {
	// make sure we save status update (and possible new DD), even once River has
	// cancelled the job: a mint it sent must be recorded
	defer (func() {
		saveCtx, cancel := afterSendContext(ctx)
		defer cancel()
		_ = w.update(saveCtx, record, args, boil.Whitelist(dbmodels.OnboardingColumns.OnboardingStatus, dbmodels.OnboardingColumns.VehicleTokenID, dbmodels.OnboardingColumns.SyntheticTokenID, dbmodels.OnboardingColumns.WalletIndex))
	})()

	w.logger.Debug().Str(logfields.VIN, args.VIN).Msg("Minting OnboardingService with SD")

	deviceDefinition, err := w.identity.FetchDeviceDefinitionByID(record.DeviceDefinitionID.String)
	if err != nil {
		w.logger.Error().Err(err).Msg("Failed to fetch device definition")
		return nil, mintNotSent(record, err)
	}

	integrationOrConnectionID, ok := new(big.Int).SetString(w.settings.ConnectionTokenID, 10)
	if !ok {
		w.logger.Error().Msg("Failed to set integration or connection token ID")
		return nil, mintNotSent(record, fmt.Errorf("invalid connection token ID %q", w.settings.ConnectionTokenID))
	}

	err = w.mint(ctx, record, args, func(sdIndex uint32, sdAddress common.Address) (sendMint, error) {
		if record.VehicleTokenID.Valid {
			return nil, fmt.Errorf("the record got vehicle %d while its mint waited", record.VehicleTokenID.Int64)
		}

		sdTypedData := w.tr.GetMintVehicleAndSDTypedDataV2(integrationOrConnectionID)
		sdSignature, err := w.ws.SignTypedData(ctx, *sdTypedData, sdIndex)
		if err != nil {
			w.logger.Error().Err(err).Msg("Failed to sign SD typed data")
			return nil, err
		}

		mintInput := registry.MintVehicleAndSdWithDdInput{
			Owner:               args.Owner,
			VehicleOwnerSig:     args.Signature,
			ManufacturerNode:    new(big.Int).SetUint64(deviceDefinition.Manufacturer.TokenID),
			IntegrationNode:     integrationOrConnectionID,
			DeviceDefinitionId:  deviceDefinition.DeviceDefinitionID,
			SyntheticDeviceAddr: sdAddress,
			SyntheticDeviceSig:  sdSignature,
			AttrInfoPairsDevice: make([]registry.AttributeInfoPair, 0),
			AttrInfoPairsVehicle: []registry.AttributeInfoPair{
				{
					Attribute: "Make",
					Info:      deviceDefinition.Manufacturer.Name,
				},
				{
					Attribute: "Model",
					Info:      deviceDefinition.Model,
				},
				{
					Attribute: "Year",
					Info:      strconv.Itoa(deviceDefinition.Year),
				},
			},
		}
		w.logger.Debug().Str(logfields.VIN, args.VIN).Str(logfields.FunctionName, "MintVehicleWithSDAndUpdate").
			Interface("mintInput", mintInput).Msg("Minting OnboardingService with SD Input")

		if args.Sacd == nil {
			return func() (*big.Int, *big.Int, error) {
				_, result, err := w.tr.MintVehicleAndSDWithDD(&mintInput, true, true)
				if err != nil || result == nil {
					return nil, nil, err
				}
				return result.VehicleId, result.SyntheticDeviceNode, nil
			}, nil
		}

		sacdInput := registry.SacdInput{
			Grantee:     args.Sacd.Grantee,
			Permissions: args.Sacd.Permissions,
			Expiration:  args.Sacd.Expiration,
			Source:      args.Sacd.Source,
		}

		w.logger.Debug().Str(logfields.VIN, args.VIN).Str(logfields.FunctionName, "MintVehicleWithSDAndUpdate").
			Interface("sacd", sacdInput).Msg("SACD provided")

		return func() (*big.Int, *big.Int, error) {
			_, result, err := w.tr.MintVehicleAndSDWithDDAndSACD(&mintInput, sacdInput, true, true)
			if err != nil || result == nil {
				return nil, nil, err
			}
			return result.VehicleId, result.SyntheticDeviceNode, nil
		}, nil
	})
	if err != nil {
		return nil, err
	}

	w.logger.Debug().Str(logfields.VIN, args.VIN).Int64(logfields.VehicleTokenID, record.VehicleTokenID.Int64).Msg("OnboardingService minted")
	w.logger.Debug().Str(logfields.VIN, args.VIN).Int64("syntheticDeviceTokenId", record.SyntheticTokenID.Int64).Msg("SD minted")

	return record, nil
}

func (w *OnboardingWorker) MintSDAndUpdate(ctx context.Context, record *dbmodels.Onboarding, args OnboardingArgs) (vinRecord *dbmodels.Onboarding, err error) {
	// make sure we save status update (and possible new DD), even once River has
	// cancelled the job: a mint it sent must be recorded
	defer (func() {
		saveCtx, cancel := afterSendContext(ctx)
		defer cancel()
		_ = w.update(saveCtx, record, args, boil.Whitelist(dbmodels.OnboardingColumns.OnboardingStatus, dbmodels.OnboardingColumns.VehicleTokenID, dbmodels.OnboardingColumns.SyntheticTokenID, dbmodels.OnboardingColumns.WalletIndex))
	})()

	w.logger.Debug().Str(logfields.VIN, args.VIN).Msg("Minting SD")

	integrationOrConnectionID, ok := new(big.Int).SetString(w.settings.ConnectionTokenID, 10)
	if !ok {
		w.logger.Error().Msg("Failed to set integration or connection token ID")
		return nil, mintNotSent(record, fmt.Errorf("invalid connection token ID %q", w.settings.ConnectionTokenID))
	}

	err = w.mint(ctx, record, args, func(sdIndex uint32, sdAddress common.Address) (sendMint, error) {
		if !record.VehicleTokenID.Valid {
			return nil, errors.New("the record lost its vehicle while its mint waited")
		}
		vehicleNode := big.NewInt(record.VehicleTokenID.Int64)

		sdTypedData := w.tr.GetMintSDTypedDataV2(integrationOrConnectionID, vehicleNode)
		sdSignature, err := w.ws.SignTypedData(ctx, *sdTypedData, sdIndex)
		if err != nil {
			w.logger.Error().Err(err).Msg("Failed to sign SD typed data")
			return nil, err
		}

		mintInput := registry.MintSyntheticDeviceInput{
			VehicleOwnerSig:     args.Signature,
			SyntheticDeviceAddr: sdAddress,
			SyntheticDeviceSig:  sdSignature,
			AttrInfoPairs:       make([]registry.AttributeInfoPair, 0),
			IntegrationNode:     integrationOrConnectionID,
			VehicleNode:         vehicleNode,
		}

		return func() (*big.Int, *big.Int, error) {
			_, result, err := w.tr.MintSD(&mintInput, true, true)
			if err != nil || result == nil {
				return nil, nil, err
			}
			return nil, result.SyntheticDeviceNode, nil
		}, nil
	})
	if err != nil {
		return nil, err
	}

	w.logger.Debug().Str(logfields.VIN, args.VIN).Int64("syntheticDeviceTokenId", record.SyntheticTokenID.Int64).Msg("SD minted")

	return record, nil
}

// sendMint sends a prepared mint's user operation. It returns the minted vehicle,
// if the mint made one, and SD, or no SD if the receipt was lost.
type sendMint func() (vehicleTokenID, sdTokenID *big.Int, err error)

// mint runs the record's mint, made by prepare for the SD wallet index and its
// address, at most once. The SD address does that: the registry mints an address
// only once, and a record keeps the SD wallet index it was first given until its
// mint is recorded, so every mint of the record, from any job, sends the same
// address. A mint already on chain is recorded instead of sent again.
//
// It runs under w.m, so mints go one at a time, and saves the record MintPending,
// with its wallet index, right before it sends. A job killed after that leaves a
// record that says a mint may be on chain; one killed before it, waiting on w.m
// say, leaves a record that says nothing was sent. MintRecovery settles both.
func (w *OnboardingWorker) mint(ctx context.Context, record *dbmodels.Onboarding, args OnboardingArgs, prepare func(sdIndex uint32, sdAddress common.Address) (sendMint, error)) error {
	w.m.Lock()
	defer w.m.Unlock()

	// Another job for the VIN may have minted while this one waited.
	current, err := dbmodels.FindOnboarding(ctx, w.dbs.DBS().Writer, args.VIN)
	if err != nil {
		return mintNotSent(record, fmt.Errorf("failed to reload VIN record: %w", err))
	}
	*record = *current
	if record.OnboardingStatus == OnboardingStatusMintSuccess && record.SyntheticTokenID.Valid {
		return nil
	}
	// River cancels a job at its timeout. This one may have waited that long, and
	// past it recovery takes the job for dead.
	if err := ctx.Err(); err != nil {
		return mintNotSent(record, err)
	}

	sdIndex, err := w.sdWalletIndex(ctx, record)
	if err != nil {
		return mintNotSent(record, err)
	}
	sdAddress, err := w.ws.GetAddress(ctx, sdIndex)
	if err != nil {
		w.logger.Error().Err(err).Msg("Failed to get SD wallet address")
		return mintNotSent(record, err)
	}
	logger := w.logger.With().Str(logfields.VIN, args.VIN).Uint32("walletIndex", sdIndex).Str("sdAddress", sdAddress.Hex()).Logger()

	// An earlier job may have sent this mint and died, or lost its receipt.
	if found, err := service.RecordChainMint(ctx, w.chain, record, sdAddress); err != nil || found {
		if err != nil {
			logger.Error().Err(err).Msg("Failed to look for the mint on chain; not minting.")
			return mintNotSent(record, err)
		}
		logger.Warn().Int64(logfields.VehicleTokenID, record.VehicleTokenID.Int64).Int64("syntheticDeviceTokenId", record.SyntheticTokenID.Int64).
			Msg("Mint is on chain already; recorded it instead of minting again.")
		return nil
	}

	send, err := prepare(sdIndex, sdAddress)
	if err != nil {
		return mintNotSent(record, err)
	}

	readStatus := record.OnboardingStatus
	record.OnboardingStatus = OnboardingStatusMintPending
	if err := w.update(ctx, record, args, boil.Whitelist(dbmodels.OnboardingColumns.OnboardingStatus, dbmodels.OnboardingColumns.WalletIndex)); err != nil {
		record.OnboardingStatus = readStatus
		return mintNotSent(record, err)
	}

	vehicleTokenID, sdTokenID, err := send()
	if err == nil && sdTokenID != nil {
		if vehicleTokenID != nil {
			record.VehicleTokenID = null.Int64From(vehicleTokenID.Int64())
		}
		record.SyntheticTokenID = null.Int64From(sdTokenID.Int64())
		record.OnboardingStatus = OnboardingStatusMintSuccess
		return nil
	}

	// The mint may be on chain all the same: its receipt was lost, or the send
	// failed after the bundler took it, or another mint of this address landed first.
	lookupCtx, cancel := afterSendContext(ctx)
	defer cancel()
	found, lookupErr := service.RecordChainMint(lookupCtx, w.chain, record, sdAddress)
	if found {
		logger.Warn().AnErr("mintError", err).Int64(logfields.VehicleTokenID, record.VehicleTokenID.Int64).Int64("syntheticDeviceTokenId", record.SyntheticTokenID.Int64).
			Msg("Mint didn't return its result, but it's on chain; recorded it.")
		return nil
	}
	if lookupErr != nil {
		logger.Error().Err(lookupErr).Msg("Failed to look for the mint on chain.")
	}
	if err != nil {
		// The record keeps its wallet index: should this mint land after all, the
		// next one sends the same SD address and can't land too.
		logger.Error().Err(err).Msg("Failed to mint")
		record.OnboardingStatus = OnboardingStatusMintFailure
		return err
	}
	return w.markMintResultUnknown(record, args, sdIndex, sdAddress)
}

// mintNotSent ends a mint attempt that sent nothing. The record is marked failed,
// unless an earlier job marked it sent: that mint may be on chain, which the next
// mint or MintRecovery looks for.
func mintNotSent(record *dbmodels.Onboarding, err error) error {
	if !service.IsMintSent(record.OnboardingStatus) {
		record.OnboardingStatus = OnboardingStatusMintFailure
	}
	return err
}

// afterSendTimeout bounds the chain lookup and save that follow a mint's send.
const afterSendTimeout = 30 * time.Second

// afterSendContext is for what follows a mint's send: it outlives River cancelling
// the job, since a mint that was sent has to be recorded.
func afterSendContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), afterSendTimeout)
}

// sdWalletIndex returns the record's SD wallet index, allocating one if the record
// has none. A new index is saved right away, unless a concurrent job for the VIN
// saved one first, which this job then uses too.
func (w *OnboardingWorker) sdWalletIndex(ctx context.Context, record *dbmodels.Onboarding) (uint32, error) {
	if record.WalletIndex.Valid {
		return uint32(record.WalletIndex.Int64), nil
	}

	next, err := w.GetNextSDWalletIndex(ctx)
	if err != nil {
		w.logger.Error().Err(err).Msg("Failed to get next SD wallet index")
		return 0, err
	}

	saved, err := dbmodels.Onboardings(
		dbmodels.OnboardingWhere.Vin.EQ(record.Vin),
		dbmodels.OnboardingWhere.WalletIndex.IsNull(),
	).UpdateAll(ctx, w.dbs.DBS().Writer, dbmodels.M{dbmodels.OnboardingColumns.WalletIndex: int64(next.NextVal)})
	if err != nil {
		return 0, fmt.Errorf("failed to save SD wallet index: %w", err)
	}
	if saved == 0 {
		current, err := dbmodels.FindOnboarding(ctx, w.dbs.DBS().Writer, record.Vin)
		if err != nil {
			return 0, fmt.Errorf("failed to reload VIN record: %w", err)
		}
		if !current.WalletIndex.Valid {
			return 0, errors.New("failed to save SD wallet index")
		}
		record.WalletIndex = current.WalletIndex
		return uint32(current.WalletIndex.Int64), nil
	}

	record.WalletIndex = null.Int64From(int64(next.NextVal))
	return next.NextVal, nil
}

func (w *OnboardingWorker) ConnectToVendorAndUpdate(ctx context.Context, record *dbmodels.Onboarding, args OnboardingArgs) (*dbmodels.Onboarding, error) {
	w.logger.Debug().Str(logfields.VIN, args.VIN).Msg("Connecting to vendor")

	// make sure we save status update (and possible new DD)
	defer (func() { _ = w.update(ctx, record, args, boil.Whitelist(dbmodels.OnboardingColumns.OnboardingStatus)) })()

	record.OnboardingStatus = OnboardingStatusConnectUnknown

	//if w.settings.EnableVendorConnection {
	//	connection, err := w.vendor.Connect([]string{args.VIN})
	//	if err != nil {
	//		w.logger.Error().Err(err).Msg("Failed to connect to vendor")
	//		record.OnboardingStatus = OnboardingStatusConnectFailure
	//		return nil, err
	//	}
	//
	//	w.logger.Debug().Str(logfields.VIN, args.VIN).Interface("connection-result", connection).Msg("Vendor connected")
	//} else {
	//	w.logger.Debug().Str(logfields.VIN, args.VIN).Msg("Vendor connection is disabled, skipping")
	//	record.ConnectionStatus = null.String{String: "succeeded", Valid: true}
	//	record.DisconnectionStatus = null.String{String: "", Valid: false}
	//	err := w.update(ctx, record, args, boil.Whitelist(dbmodels.OnboardingColumns.ConnectionStatus, dbmodels.OnboardingColumns.DisconnectionStatus))
	//	if err != nil {
	//		w.logger.Error().Err(err).Msg("Failed to update connection status")
	//		record.OnboardingStatus = OnboardingStatusConnectFailure
	//		return nil, err
	//	}
	//}

	record.OnboardingStatus = OnboardingStatusConnectSuccess

	return record, nil
}

// errMintResultUnknown: the mint was sent, but its result didn't come back.
var errMintResultUnknown = errors.New("mint sent but its result is unknown")

// markMintResultUnknown handles a mint that returned no error and no result, and
// isn't on chain yet. The transactions client does that when the user operation
// was sent but its receipt poll failed, so the mint may still land. The record is
// parked at MintUnknown, which isn't resubmitted, with its SD wallet index saved:
// MintRecovery looks the SD up on chain by its address once the job is done.
func (w *OnboardingWorker) markMintResultUnknown(record *dbmodels.Onboarding, args OnboardingArgs, sdIndex uint32, sdAddress common.Address) error {
	record.WalletIndex = null.Int64From(int64(sdIndex))
	record.OnboardingStatus = OnboardingStatusMintUnknown
	w.logger.Error().
		Str(logfields.VIN, args.VIN).
		Str("sdAddress", sdAddress.Hex()).
		Uint32("walletIndex", sdIndex).
		Msg("Mint sent but its result was lost; not retrying. Look the SD up by its address.")
	return errMintResultUnknown
}

type SDWalletIndex struct {
	NextVal uint32 `boil:"nextval"`
}

func (w *OnboardingWorker) GetNextSDWalletIndex(ctx context.Context) (*SDWalletIndex, error) {
	tx, err := w.dbs.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		w.logger.Error().Err(err).Msg("Failed to begin transaction")
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil && err == nil {
				w.logger.Error().Err(rbErr).Msg("Failed to rollback transaction")
			}
		}
	}()

	index := SDWalletIndex{}
	qry := fmt.Sprintf("SELECT nextval('%s.sd_wallet_index_seq');", w.settings.DB.Name)
	err = queries.Raw(qry).Bind(ctx, w.dbs.DBS().Reader, &index)
	if err != nil {
		w.logger.Error().Err(err).Msg("Failed to get next SD wallet index")
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		w.logger.Error().Err(err).Msg("Failed to commit transaction")
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return &index, nil
}

func (w *OnboardingWorker) update(ctx context.Context, record *dbmodels.Onboarding, args OnboardingArgs, columns boil.Columns) error {
	if _, err := record.Update(ctx, w.dbs.DBS().Writer, columns); err != nil {
		w.logger.Error().Err(err).Str(logfields.VIN, args.VIN).Msg("Failed to update VIN record")
		return fmt.Errorf("failed to update VIN record: %w", err)
	}

	w.logger.Debug().Str(logfields.VIN, args.VIN).Msg("VIN record updated")

	return nil
}
