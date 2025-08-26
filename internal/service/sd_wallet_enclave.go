package service

import (
	"context"

	pb "github.com/DIMO-Network/synthetic-wallet-instance/pkg/grpc"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/ethereum/go-ethereum/common"
	signer "github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type SDWalletEnclave struct {
	logger *zerolog.Logger
	rpc    pb.SyntheticWalletClient
}

func NewSDWalletEnclaveClient(logger *zerolog.Logger, settings config.Settings) (*SDWalletEnclave, error) {
	conn, err := grpc.NewClient(settings.SyntheticWalletGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return &SDWalletEnclave{
		logger: logger,
		rpc:    pb.NewSyntheticWalletClient(conn),
	}, nil
}

var zeroAddr common.Address

func (s *SDWalletEnclave) GetAddress(ctx context.Context, index uint32) (common.Address, error) {
	resp, err := s.rpc.GetAddress(ctx, &pb.GetAddressRequest{ChildNumber: index})
	if err != nil {
		return zeroAddr, err
	}

	return common.BytesToAddress(resp.Address), nil
}

func (s *SDWalletEnclave) SignHash(ctx context.Context, hash []byte, index uint32) ([]byte, error) {
	resp, err := s.rpc.SignHash(ctx, &pb.SignHashRequest{
		ChildNumber: index,
		Hash:        hash,
	})
	if err != nil {
		return nil, err
	}

	return resp.Signature, nil
}

func (s *SDWalletEnclave) SignTypedData(ctx context.Context, data signer.TypedData, index uint32) ([]byte, error) {
	hash, _, err := signer.TypedDataAndHash(data)
	if err != nil {
		return nil, err
	}

	return s.SignHash(ctx, hash, index)
}
