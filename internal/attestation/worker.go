package attestation

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/shared/pkg/logfields"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/riverqueue/river"
	"github.com/rs/zerolog"
)

type DDAttestArgs struct {
	VehicleTokenID     int64  `json:"vehicleTokenId"`
	DeviceDefinitionID string `json:"deviceDefinitionId"`
}

func (DDAttestArgs) Kind() string { return "device_definition_attest" }

func (DDAttestArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: 5,
	}
}

type DDAttestWorker struct {
	logger     zerolog.Logger
	identity   service.IdentityAPIService
	dis        *DISClient
	privateKey *ecdsa.PrivateKey
	source     string
	chainID    uint64
	vehicleNFT common.Address

	river.WorkerDefaults[DDAttestArgs]
}

func NewDDAttestWorker(logger zerolog.Logger, settings *config.Settings, identity service.IdentityAPIService) (*DDAttestWorker, error) {
	if settings.DeveloperPK == "" {
		return nil, fmt.Errorf("DEVELOPER_PK is required")
	}
	pk, err := crypto.HexToECDSA(settings.DeveloperPK)
	if err != nil {
		return nil, fmt.Errorf("parse DEVELOPER_PK: %w", err)
	}
	source := crypto.PubkeyToAddress(pk.PublicKey).Hex()

	disURL := settings.DISAttestationURL
	if disURL.String() == "" {
		return nil, fmt.Errorf("DIS_ATTESTATION_URL is required")
	}
	dexURL := settings.DexURL
	if dexURL.String() == "" {
		return nil, fmt.Errorf("DEX_URL is required")
	}
	if settings.DevLicenseRedirectURL == "" {
		return nil, fmt.Errorf("DEV_LICENSE_REDIRECT_URL is required")
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	dexBase := dexURL
	dex := NewDexClient(httpClient, &dexBase, settings.DevLicenseRedirectURL, pk, source)
	disBase := disURL
	dis := NewDISClient(httpClient, &disBase, dex)

	return &DDAttestWorker{
		logger:     logger,
		identity:   identity,
		dis:        dis,
		privateKey: pk,
		source:     source,
		chainID:    uint64(settings.ChainID),
		vehicleNFT: settings.VehicleNftAddress,
	}, nil
}

func (w *DDAttestWorker) Timeout(*river.Job[DDAttestArgs]) time.Duration { return 2 * time.Minute }

func (w *DDAttestWorker) Work(ctx context.Context, job *river.Job[DDAttestArgs]) error {
	args := job.Args
	log := w.logger.With().
		Int64(logfields.VehicleTokenID, args.VehicleTokenID).
		Str(logfields.DefinitionID, args.DeviceDefinitionID).
		Str(logfields.FunctionName, "DDAttestWorker.Work").
		Logger()

	def, err := w.identity.FetchDeviceDefinitionByID(args.DeviceDefinitionID)
	if err != nil {
		return fmt.Errorf("fetch device definition: %w", err)
	}

	data, err := json.Marshal(def)
	if err != nil {
		return fmt.Errorf("marshal device definition: %w", err)
	}

	subject := buildVehicleDID(w.chainID, w.vehicleNFT, args.VehicleTokenID)
	event, err := NewSignedEvent(subject, w.source, EventTypeDeviceDefinition, data, w.privateKey)
	if err != nil {
		return fmt.Errorf("build cloud event: %w", err)
	}

	if err := w.dis.UploadAttestation(ctx, event); err != nil {
		return fmt.Errorf("upload attestation: %w", err)
	}

	log.Info().Str("subject", subject).Msg("Uploaded device definition attestation")
	return nil
}

func buildVehicleDID(chainID uint64, contract common.Address, tokenID int64) string {
	did := cloudevent.ERC721DID{
		ChainID:         chainID,
		ContractAddress: contract,
		TokenID:         big.NewInt(tokenID),
	}
	return did.String()
}
