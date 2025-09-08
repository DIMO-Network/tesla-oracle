package service

import "github.com/friendsofgo/errors"

// Domain errors for Tesla Oracle application
var (
	ErrBadRequest               = errors.New("bad request")
	ErrUnauthorized             = errors.New("unauthorized access")
	ErrDevLicenseNotAllowed     = errors.New("dev license not allowed for this operation")
	ErrVehicleNotFound          = errors.New("vehicle not found")
	ErrSyntheticDeviceNotFound  = errors.New("synthetic device not found")
	ErrVehicleOwnershipMismatch = errors.New("vehicle does not belong to authenticated user")
	ErrNoCredentials            = errors.New("no credentials found for vehicle")
	ErrCredentialDecryption     = errors.New("failed to decrypt credentials")
	ErrTokenExpired             = errors.New("refresh token has expired")
	ErrTokenRefreshFailed       = errors.New("failed to refresh access token")
	ErrFleetStatusCheck         = errors.New("error checking fleet status")
	ErrTelemetryNotReady        = errors.New("vehicle not ready for telemetry subscription")
	ErrTelemetryLimitReached    = errors.New("telemetry subscription limit reached")
	ErrTelemetryConfigFailed    = errors.New("failed to update telemetry configuration")
	ErrSubscriptionStatusUpdate = errors.New("failed to update subscription status")
	ErrPartnersToken            = errors.New("failed to get partners token")
	ErrTelemetryUnsubscribe     = errors.New("failed to unsubscribe from telemetry data")
	ErrDeviceDefinitionNotFound = errors.New("device definition not found")
	ErrCredentialStore          = errors.New("failed to store credentials")
	ErrOAuthVehiclesFetch       = errors.New("failed to fetch vehicles from Tesla")
	ErrOnboardingRecordCreation = errors.New("failed to create onboarding record")
	ErrVINDecoding              = errors.New("failed to decode VIN")
	ErrUnsupportedCommand       = errors.New("unsupported command")
	ErrInactiveSubscription     = errors.New("vehicle subscription is not active")
)
