package service

import (
	"context"
	"fmt"

	dagrpc "github.com/DIMO-Network/devices-api/pkg/grpc"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"sync"
)

type DevicesGRPCService interface {
	StopTeslaTask(ctx context.Context, tokenID int64) error
	StartTeslaTask(ctx context.Context, tokenID int64) error
}

type devicesGRPCService struct {
	log      *zerolog.Logger
	settings *config.Settings
	conn     *grpc.ClientConn
	client   dagrpc.TeslaServiceClient
	mu       sync.Mutex
}

func NewDevicesGRPCService(settings *config.Settings, log *zerolog.Logger) (DevicesGRPCService, error) {
	if settings.DevicesGRPCEndpoint == "" {
		return nil, fmt.Errorf("DevicesGRPCEndpoint is not configured")
	}

	conn, err := grpc.NewClient(settings.DevicesGRPCEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to devices gRPC endpoint: %w", err)
	}

	client := dagrpc.NewTeslaServiceClient(conn)

	return &devicesGRPCService{
		log:      log,
		settings: settings,
		conn:     conn,
		client:   client,
	}, nil
}

func (d *devicesGRPCService) StopTeslaTask(ctx context.Context, tokenID int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.client.StopTask(ctx, &dagrpc.StopTaskRequest{VehicleTokenId: tokenID})
	if err != nil {
		d.log.Error().Err(err).Int64("tokenID", tokenID).Msg("failed to stop Tesla task")
		return fmt.Errorf("failed to stop Tesla task: %w", err)
	}

	d.log.Info().Int64("tokenID", tokenID).Msg("successfully stopped Tesla task")
	return nil
}

func (d *devicesGRPCService) StartTeslaTask(ctx context.Context, tokenID int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.client.StartTask(ctx, &dagrpc.StartTaskRequest{VehicleTokenId: tokenID})
	if err != nil {
		d.log.Error().Err(err).Int64("tokenID", tokenID).Msg("failed to start Tesla task")
		return fmt.Errorf("failed to start Tesla task: %w", err)
	}

	d.log.Info().Int64("tokenID", tokenID).Msg("successfully started Tesla task")
	return nil
}

func (d *devicesGRPCService) Close() error {
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}
