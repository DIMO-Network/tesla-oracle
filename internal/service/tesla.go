package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/rs/zerolog"
	"regexp"
	"strconv"
)

type TeslaService struct {
	settings *config.Settings
	logger   *zerolog.Logger
	Cipher   cipher.Cipher
	pdb      *db.Store
}

func NewTeslaService(settings *config.Settings, logger *zerolog.Logger, cipher cipher.Cipher, pdb *db.Store) *TeslaService {
	return &TeslaService{
		settings: settings,
		logger:   logger,
		Cipher:   cipher,
		pdb:      pdb,
	}
}

type VirtualKeyStatus int

const (
	Incapable VirtualKeyStatus = iota
	Paired
	Unpaired
)

// GetVehicleByVIN retrieves a vehicle by its VIN.
func (ts *TeslaService) GetVehicleByVIN(ctx context.Context, logger *zerolog.Logger, pdb *db.Store, vin string) (*dbmodels.SyntheticDevice, error) {
	tx, err := pdb.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to begin transaction for vehicle %s", vin)
		return nil, err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				logger.Error().Err(rbErr).Msgf("GetVehicleByVIN: Failed to rollback transaction for vehicle %s", vin)
			}
		} else {
			if cmErr := tx.Commit(); cmErr != nil {
				logger.Error().Err(cmErr).Msgf("GetVehicleByVIN: Failed to commit transaction for vehicle %s", vin)
			}
		}
	}()

	sd, err := dbmodels.SyntheticDevices(
		dbmodels.SyntheticDeviceWhere.Vin.EQ(vin)).One(ctx, tx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVehicleNotFound
		}
		logger.Error().Err(err).Msgf("Failed to check if vehicle %s has been processed", vin)
		return nil, err
	}

	return sd, nil
}

func (s VirtualKeyStatus) String() string {
	switch s {
	case Incapable:
		return "Incapable"
	case Paired:
		return "Paired"
	case Unpaired:
		return "Unpaired"
	}
	return ""
}

func (s VirtualKeyStatus) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s *VirtualKeyStatus) UnmarshalText(text []byte) error {
	switch str := string(text); str {
	case "Incapable":
		*s = Incapable
	case "Paired":
		*s = Paired
	case "Unpaired":
		*s = Unpaired
	default:
		return fmt.Errorf("unrecognized status %q", str)
	}
	return nil
}

func IsFleetTelemetryCapable(fs *VehicleFleetStatus) bool {
	// We used to check for the presence of a meaningful value (not ""
	// or "unknown") for fleet_telemetry_version, but this started
	// populating on old cars that are not capable of streaming.
	return fs.VehicleCommandProtocolRequired || !fs.DiscountedDeviceData
}

var teslaFirmwareStart = regexp.MustCompile(`^(\d{4})\.(\d+)`)

func IsFirmwareFleetTelemetryCapable(v string) (bool, error) {
	m := teslaFirmwareStart.FindStringSubmatch(v)
	if len(m) == 0 {
		return false, fmt.Errorf("unexpected firmware version format %q", v)
	}

	year, err := strconv.Atoi(m[1])
	if err != nil {
		return false, fmt.Errorf("couldn't parse year %q", m[1])
	}

	week, err := strconv.Atoi(m[2])
	if err != nil {
		return false, fmt.Errorf("couldn't parse week %q", m[2])
	}

	return year > 2024 || year == 2024 && week >= 26, nil
}
