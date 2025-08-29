package bootstrap

import (
	"context"
	"fmt"

	"github.com/DIMO-Network/go-transactions"
	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/onboarding"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/rs/zerolog"
)

// Services holds all initialized services
type Services struct {
	DB                       *db.Store
	TransactionsClient       *transactions.Client
	OnboardingService        *service.OnboardingService
	IdentityService          service.IdentityAPIService
	DeviceDefinitionsService service.DeviceDefinitionsAPIService
	WalletService            service.SDWalletsAPI
	RiverClient              *river.Client[pgx.Tx]
	DBPool                   *pgxpool.Pool
}

// InitializeServices creates and initializes all application services
func InitializeServices(ctx context.Context, logger *zerolog.Logger, settings *config.Settings) (*Services, error) {
	// Initialize database
	pdb := db.NewDbConnectionFromSettings(ctx, &settings.DB, true)
	pdb.WaitForDB(*logger)

	// Initialize transactions client
	transactionsClient, err := onboarding.NewTransactionsClient(settings)
	if err != nil {
		return nil, fmt.Errorf("failed to create transactions client: %w", err)
	}

	// Initialize services
	onboardingService := service.NewOnboardingService(&pdb, logger)
	identityService := service.NewIdentityAPIService(logger, settings)
	deviceDefinitionsService := service.NewDeviceDefinitionsAPIService(logger, settings)

	// Initialize wallet service
	walletService, err := service.NewSDWalletEnclaveClient(logger, *settings)
	if err != nil {
		return nil, fmt.Errorf("failed to create SD Wallets service: %w", err)
	}

	// Initialize River client with workers
	riverClient, dbPool, err := initializeRiver(ctx, *logger, settings, identityService, &pdb, transactionsClient, walletService)
	if err != nil {
		return nil, fmt.Errorf("failed to create river client: %w", err)
	}

	return &Services{
		DB:                       &pdb,
		TransactionsClient:       transactionsClient,
		OnboardingService:        onboardingService,
		IdentityService:          identityService,
		DeviceDefinitionsService: deviceDefinitionsService,
		WalletService:            walletService,
		RiverClient:              riverClient,
		DBPool:                   dbPool,
	}, nil
}

// initializeRiver creates River client with workers and database pool
func initializeRiver(ctx context.Context, logger zerolog.Logger, settings *config.Settings, identityService service.IdentityAPIService, dbs *db.Store, tr *transactions.Client, ws service.SDWalletsAPI) (*river.Client[pgx.Tx], *pgxpool.Pool, error) {
	workers := river.NewWorkers()

	// Create and register workers
	onboardingWorker := onboarding.NewOnboardingWorker(settings, logger, identityService, dbs, tr, ws)
	if err := river.AddWorkerSafely(workers, onboardingWorker); err != nil {
		return nil, nil, fmt.Errorf("failed to add onboarding worker: %w", err)
	}
	logger.Debug().Msg("Added onboarding worker")

	// Create database pool
	dbURL := settings.DB.BuildConnectionString(true)
	dbPool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	logger.Debug().Msg("DB pool for workers created")

	// Create River client
	riverClient, err := river.NewClient(riverpgxv5.New(dbPool), &river.Config{
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: 100},
		},
		Workers: workers,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create river client: %w", err)
	}

	return riverClient, dbPool, nil
}

// Cleanup properly closes all services
func (s *Services) Cleanup() {
	if s.DBPool != nil {
		s.DBPool.Close()
	}
	if s.DB != nil {
		_ = s.DB.DBS().Writer.Close()
		_ = s.DB.DBS().Reader.Close()
	}
}
