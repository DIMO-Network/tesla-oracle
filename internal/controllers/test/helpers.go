package test

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/token-exchange-api/pkg/tokenclaims"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"

	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/docker/go-connections/nat"
	"github.com/pkg/errors"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const testDbName = "tesla_oracle"

// StartContainerDatabase starts postgres container with default test settings, and migrates the db. Caller must terminate container.
func StartContainerDatabase(ctx context.Context, t *testing.T, migrationsDirRelPath string) (db.Store, testcontainers.Container, config.Settings) {
	settings := GetTestDbSettings()
	pgPort := "5432/tcp"
	dbURL := func(_ string, port nat.Port) string {
		return fmt.Sprintf("postgres://%s:%s@localhost:%s/%s?sslmode=disable", settings.DB.User, settings.DB.Password, port.Port(), settings.DB.Name)
	}
	cr := testcontainers.ContainerRequest{
		Image:        "postgres:16.6-alpine",
		Env:          map[string]string{"POSTGRES_USER": settings.DB.User, "POSTGRES_PASSWORD": settings.DB.Password, "POSTGRES_DB": settings.DB.Name},
		ExposedPorts: []string{pgPort},
		Cmd:          []string{"postgres", "-c", "fsync=off"},
		WaitingFor:   wait.ForSQL(nat.Port(pgPort), "postgres", dbURL),
	}

	pgContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: cr,
		Started:          true,
	})
	if err != nil {
		return handleContainerStartErr(ctx, err, pgContainer, settings, t)
	}
	mappedPort, err := pgContainer.MappedPort(ctx, nat.Port(pgPort))
	if err != nil {
		return handleContainerStartErr(ctx, errors.Wrap(err, "failed to get container external port"), pgContainer, settings, t)
	}
	fmt.Printf("postgres container session %s ready and running at port: %s \n", pgContainer.SessionID(), mappedPort)
	//defer pgContainer.Terminate(ctx) // this should be done by the caller

	settings.DB.Port = mappedPort.Port()
	pdb := db.NewDbConnectionForTest(ctx, &settings.DB, false)
	for !pdb.IsReady() {
		time.Sleep(500 * time.Millisecond)
	}
	// can't connect to db, dsn=user=postgres password=postgres dbname=tesla_oracle host=localhost port=49395 sslmode=disable search_path=tesla_oracle, err=EOF
	// error happens when calling here
	_, err = pdb.DBS().Writer.Exec(`
		grant usage on schema public to public;
		grant create on schema public to public;
		CREATE SCHEMA IF NOT EXISTS tesla_oracle;
		ALTER USER postgres SET search_path = tesla_oracle, public;
		SET search_path = tesla_oracle, public;
		`)
	if err != nil {
		return handleContainerStartErr(ctx, errors.Wrapf(err, "failed to apply schema. session: %s, port: %s",
			pgContainer.SessionID(), mappedPort.Port()), pgContainer, settings, t)
	}
	// add truncate tables func
	_, err = pdb.DBS().Writer.Exec(`
CREATE OR REPLACE FUNCTION truncate_tables() RETURNS void AS $$
DECLARE
    statements CURSOR FOR
        SELECT tablename FROM pg_tables
        WHERE schemaname = 'tesla_oracle' and tablename != 'migrations';
BEGIN
    FOR stmt IN statements LOOP
        EXECUTE 'TRUNCATE TABLE ' || quote_ident(stmt.tablename) || ' CASCADE;';
    END LOOP;
END;
$$ LANGUAGE plpgsql;
`)
	if err != nil {
		return handleContainerStartErr(ctx, errors.Wrap(err, "failed to create truncate func"), pgContainer, settings, t)
	}

	goose.SetTableName("tesla_oracle.migrations")
	if err := goose.RunContext(ctx, "up", pdb.DBS().Writer.DB, migrationsDirRelPath); err != nil {
		return handleContainerStartErr(ctx, errors.Wrap(err, "failed to apply goose migrations for test"), pgContainer, settings, t)
	}

	return pdb, pgContainer, settings
}

func handleContainerStartErr(ctx context.Context, err error, container testcontainers.Container, settings config.Settings, t *testing.T) (db.Store, testcontainers.Container, config.Settings) {
	if err != nil {
		fmt.Println("start container error: " + err.Error())
		if container != nil {
			container.Terminate(ctx) //nolint
		}
		t.Fatal(err)
	}
	return db.Store{}, container, settings
}

// GetTestDbSettings builds test db config.settings object
func GetTestDbSettings() config.Settings {
	dbSettings := db.Settings{
		Name:               testDbName,
		Host:               "localhost",
		Port:               "6669",
		User:               "postgres",
		Password:           "postgres",
		MaxOpenConnections: 5,
		MaxIdleConnections: 5,
	}
	settings := config.Settings{
		LogLevel: "info",
		DB:       dbSettings,
	}
	return settings
}

// TruncateTables truncates tables for the test db, useful to run as teardown at end of each DB dependent test.
func TruncateTables(db *sql.DB, t *testing.T) {
	_, err := db.Exec(`SELECT truncate_tables();`)
	if err != nil {
		fmt.Println("truncating tables failed.")
		t.Fatal(err)
	}
}

// AuthInjectorTestHandler injects fake jwt with sub
func AuthInjectorTestHandler(userID string, userEthAddr *common.Address) fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims := jwt.MapClaims{
			"sub": userID,
			"nbf": time.Now().Unix(),
		}
		if userEthAddr != nil {
			claims["ethereum_address"] = userEthAddr.Hex()
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		c.Locals("user", token)
		return c.Next()
	}
}

func BuildRequest(method, url, body string) *http.Request {
	req, _ := http.NewRequest(
		method,
		url,
		strings.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")

	return req
}

func GenerateJWT(req *http.Request) error {
	return GenerateJWTWithPermissions(req, []string{tokenclaims.PermissionGetNonLocationHistory}, "")
}

func GenerateJWTWithPermissions(req *http.Request, permissions []string, tokenID string) error {
	// Define the secret key for signing the token
	secretKey := []byte("your-secret-key")

	bigTokenId := new(big.Int) // Add token_id if provided
	if tokenID != "" {
		var ok bool
		bigTokenId, ok = big.NewInt(0).SetString(tokenID, 10)
		if !ok {
			return errors.New("failed to parse token ID")
		}
	}

	// Create claims with the new JWT structure
	claims := jwt.MapClaims{
		"aud":         []string{"dimo.zone"},
		"exp":         time.Now().Add(time.Hour).Unix(),
		"iat":         time.Now().Unix(),
		"iss":         "https://auth-roles-rights.dimo.zone",
		"permissions": permissions,
		"sub":         "0x1D18E561cF294829a7AB7a052a64F282fe245aFb",
		"asset": cloudevent.ERC721DID{
			ContractAddress: common.HexToAddress("0x45fbCD3ef7361d156e8b16F5538AE36DEdf61Da8"),
			TokenID:         bigTokenId,
			ChainID:         0,
		},
	}

	// Create a new token with the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		fmt.Println("Error signing token:", err)
		return err
	}

	fmt.Println("Valid Token:", signedToken)
	req.Header.Set("Authorization", "Bearer "+signedToken)
	return nil
}
