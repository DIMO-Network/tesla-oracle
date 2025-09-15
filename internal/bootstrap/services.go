package bootstrap

import (
	"context"
	"fmt"
	"time"

	"github.com/DIMO-Network/go-transactions"
	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/shared/pkg/redis"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/onboarding"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	work "github.com/DIMO-Network/tesla-oracle/internal/workers"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/patrickmn/go-cache"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/rs/zerolog"
)

// Services holds all initialized services
type Services struct {
	DB                       *db.Store
	TransactionsClient       *transactions.Client
	VehicleOnboardService    service.VehicleOnboardService
	IdentityService          service.IdentityAPIService
	DeviceDefinitionsService service.DeviceDefinitionsAPIService
	WalletService            service.SDWalletsAPI
	RiverClient              *river.Client[pgx.Tx]
	DBPool                   *pgxpool.Pool
	Repositories             *repository.Repositories
	TeslaFleetAPIService     core.TeslaFleetAPIService
	TeslaService             *service.TeslaService
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
	identityService := service.NewIdentityAPIService(logger, settings)
	deviceDefinitionsService := service.NewDeviceDefinitionsAPIService(logger, settings)

	// Initialize wallet service
	walletService, err := service.NewSDWalletEnclaveClient(logger, *settings)
	if err != nil {
		return nil, fmt.Errorf("failed to create SD Wallets service: %w", err)
	}

	// Initialize Tesla Fleet API service
	teslaFleetAPIService, err := core.NewTeslaFleetAPIService(settings, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create Tesla Fleet API service: %w", err)
	}

	// Initialize cipher for services that need encryption
	cip := createCipher(settings, logger)

	// Initialize repositories (moved before Tesla service since it depends on them)
	repositories := initializeRepositories(&pdb, settings, logger, cip)

	// Initialize devices GRPC service
	var devicesService service.DevicesGRPCService
	if !settings.DisableDevicesGRPC {
		devicesService, err = service.NewDevicesGRPCService(settings, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize DevicesGRPCService: %w", err)
		}
	} else {
		logger.Warn().Msgf("Devices GRPC is DISABLED")
	}

	// Initialize Tesla token manager
	tokenManager := core.NewTeslaTokenManager(cip, repositories.Vehicle, teslaFleetAPIService, logger)

	// Initialize Tesla service with all dependencies
	teslaService := service.NewTeslaService(settings, logger, repositories, teslaFleetAPIService, identityService, deviceDefinitionsService, devicesService, *tokenManager)

	// Initialize River client with workers (including Tesla command worker)
	riverClient, dbPool, err := initializeRiver(ctx, *logger, settings, identityService, &pdb, transactionsClient, walletService, teslaFleetAPIService, tokenManager, repositories)
	if err != nil {
		return nil, fmt.Errorf("failed to create river client: %w", err)
	}

	// Initialize VehicleOnboardService
	vehicleOnboardService := service.NewVehicleOnboardService(settings, logger, identityService, riverClient, walletService, transactionsClient, repositories)

	return &Services{
		DB:                       &pdb,
		TransactionsClient:       transactionsClient,
		VehicleOnboardService:    vehicleOnboardService,
		IdentityService:          identityService,
		DeviceDefinitionsService: deviceDefinitionsService,
		WalletService:            walletService,
		RiverClient:              riverClient,
		DBPool:                   dbPool,
		Repositories:             repositories,
		TeslaFleetAPIService:     teslaFleetAPIService,
		TeslaService:             teslaService,
	}, nil
}

// initializeRiver creates River client with workers and database pool
func initializeRiver(ctx context.Context, logger zerolog.Logger, settings *config.Settings, identityService service.IdentityAPIService, dbs *db.Store, tr *transactions.Client, ws service.SDWalletsAPI, teslaFleetAPI core.TeslaFleetAPIService, tokenManager *core.TeslaTokenManager, repositories *repository.Repositories) (*river.Client[pgx.Tx], *pgxpool.Pool, error) {
	workers := river.NewWorkers()

	// Create and register workers
	onboardingWorker := onboarding.NewOnboardingWorker(settings, logger, identityService, dbs, tr, ws)
	if err := river.AddWorkerSafely(workers, onboardingWorker); err != nil {
		return nil, nil, fmt.Errorf("failed to add onboarding worker: %w", err)
	}
	logger.Debug().Msg("Added onboarding worker")

	// Create and register Tesla command worker

	teslaCommandWorker := work.NewTeslaCommandWorker(teslaFleetAPI, tokenManager, repositories.Command, repositories.Vehicle, &logger, 1*time.Minute)
	if err := river.AddWorkerSafely(workers, teslaCommandWorker); err != nil {
		return nil, nil, fmt.Errorf("failed to add Tesla command worker: %w", err)
	}
	logger.Debug().Msg("Added Tesla command worker")

	// Create database pool
	dbURL := settings.DB.BuildConnectionString(true)
	dbPool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	logger.Debug().Msg("DB pool for workers created")

	// Create Tesla command error handler
	errorHandler := work.NewTeslaCommandErrorHandler(logger, repositories)

	// Create River client
	riverClient, err := river.NewClient(riverpgxv5.New(dbPool), &river.Config{
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: 100},
			"tesla_commands":   {MaxWorkers: 20}, // Dedicated queue for Tesla commands
		},
		Workers:      workers,
		ErrorHandler: errorHandler,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create river client: %w", err)
	}

	return riverClient, dbPool, nil
}

// initializeRepositories creates and initializes all repository implementations
func initializeRepositories(pdb *db.Store, settings *config.Settings, logger *zerolog.Logger, cip cipher.Cipher) *repository.Repositories {
	// Initialize vehicle repository
	vehicleRepo := repository.NewVehicleRepository(pdb, cip, logger)

	// Initialize credential repository directly
	credentialRepo := createCredentialStore(settings, logger)

	// Initialize onboarding repository
	onboardingRepo := repository.NewOnboardingRepository(pdb, logger)

	// Initialize command repository
	commandRepo := repository.NewCommandRepository(pdb, logger)

	return &repository.Repositories{
		Vehicle:    vehicleRepo,
		Credential: credentialRepo,
		Onboarding: onboardingRepo,
		Command:    commandRepo,
	}
}

// createCipher creates the appropriate cipher based on environment
func createCipher(settings *config.Settings, logger *zerolog.Logger) cipher.Cipher {
	if settings.Environment == "dev" || settings.IsProduction() {
		return createKMS(settings, logger)
	} else {
		logger.Warn().Msg("Using ROT13 encrypter. Only use this for local testing!")
		return new(cipher.ROT13Cipher)
	}
}

// createCredentialStore creates the appropriate credential store implementation
func createCredentialStore(settings *config.Settings, logger *zerolog.Logger) repository.CredentialRepository {
	cip := createCipher(settings, logger)

	// Create cache service
	cacheService := redis.NewRedisCacheService(settings.IsProduction(), redis.Settings{
		URL:       settings.RedisURL,
		Password:  settings.RedisPassword,
		TLS:       settings.RedisTLS,
		KeyPrefix: "tesla-oracle",
	})

	// Return appropriate credential store implementation
	if settings.EnableLocalCache {
		logger.Info().Msg("Using LocalCache for CredStore.")
		return &repository.TempCredsLocalStore{
			Cache:  cache.New(5*time.Minute, 10*time.Minute),
			Cipher: cip,
		}
	} else {
		logger.Info().Msg("Using redis CredStore implementation.")
		return &repository.TempCredsStore{
			Cache:  cacheService,
			Cipher: cip,
		}
	}
}

// createKMS creates a KMS cipher for encryption
func createKMS(settings *config.Settings, logger *zerolog.Logger) cipher.Cipher {
	// Need AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to be set.
	awscfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(settings.AWSRegion))
	if err != nil {
		logger.Fatal().Err(err).Msg("Couldn't create AWS config.")
	}

	return &cipher.KMSCipher{
		KeyID:  settings.KMSKeyID,
		Client: kms.NewFromConfig(awscfg),
	}
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
