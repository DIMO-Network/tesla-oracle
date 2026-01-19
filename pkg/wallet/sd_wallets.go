package wallet

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	signer "github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/rs/zerolog"
)

type SDWalletsAPI interface {
	GetAddress(ctx context.Context, index uint32) (common.Address, error)
	SignHash(ctx context.Context, hash []byte, index uint32) ([]byte, error)
	SignTypedData(ctx context.Context, data signer.TypedData, index uint32) ([]byte, error)
}

type SDWalletsService struct {
	logger zerolog.Logger
	key    *hdkeychain.ExtendedKey
}

func NewSDWalletsService(logger zerolog.Logger, rawSeed string) *SDWalletsService {
	seed := common.FromHex(rawSeed)

	key, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		logger.Fatal().Err(err).Msg("Couldn't get key for provided seed.")
		return nil
	}

	return &SDWalletsService{
		logger: logger,
		key:    key,
	}
}

func (s *SDWalletsService) GetAddress(ctx context.Context, index uint32) (common.Address, error) {
	pk, err := s.getPrivateKey(index)
	if err != nil {
		return common.Address{}, err
	}

	return crypto.PubkeyToAddress(pk.PublicKey), nil
}

func (s *SDWalletsService) SignHash(ctx context.Context, hash []byte, index uint32) ([]byte, error) {
	pk, err := s.getPrivateKey(index)
	if err != nil {
		return nil, err
	}

	sig, err := crypto.Sign(hash, pk)
	if err != nil {
		return nil, err
	}

	sig[64] += 27

	return sig, nil
}

func (s *SDWalletsService) SignTypedData(ctx context.Context, data signer.TypedData, index uint32) ([]byte, error) {
	hash, _, err := signer.TypedDataAndHash(data)
	if err != nil {
		return nil, err
	}

	return s.SignHash(ctx, hash, index)
}

func (s *SDWalletsService) getPrivateKey(index uint32) (*ecdsa.PrivateKey, error) {
	if index >= hdkeychain.HardenedKeyStart {
		return nil, fmt.Errorf("child_number %d >= 2^31", index)
	}

	childKey, err := s.key.Derive(hdkeychain.HardenedKeyStart + index)
	if err != nil {
		s.logger.Fatal().Err(err).Msg("Couldn't derive key.")
		return nil, err
	}

	pk, err := childKey.ECPrivKey()
	if err != nil {
		return nil, err
	}

	ecPk, err := crypto.ToECDSA(pk.Serialize())
	if err != nil {
		return nil, err
	}

	return ecPk, nil
}
