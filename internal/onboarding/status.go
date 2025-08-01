package onboarding

const (
	// 0-9 Initial status for submitting the job
	OnboardingStatusSubmitUnknown = 0
	OnboardingStatusSubmitPending = 1
	OnboardingStatusSubmitFailure = 2
	OnboardingStatusSubmitSuccess = 3

	// 10-19 initial VIN verification
	OnboardingStatusDecodingUnknown = 10
	OnboardingStatusDecodingPending = 11
	OnboardingStatusDecodingFailure = 12
	OnboardingStatusDecodingSuccess = 13

	// 20-29 validation in external vendor system
	OnboardingStatusVendorValidationUnknown = 20
	OnboardingStatusVendorValidationPending = 21
	OnboardingStatusVendorValidationFailure = 22
	OnboardingStatusVendorValidationSuccess = 23

	// 30-39 mint submission
	OnboardingStatusMintSubmitUnknown = 30
	OnboardingStatusMintSubmitPending = 31
	OnboardingStatusMintSubmitFailure = 32
	OnboardingStatusMintSubmitSuccess = 33

	// 40-49 vendor connection
	OnboardingStatusConnectUnknown = 40
	OnboardingStatusConnectPending = 41
	OnboardingStatusConnectFailure = 42
	OnboardingStatusConnectSuccess = 43

	// 50-59 minting
	OnboardingStatusMintUnknown = 50
	OnboardingStatusMintPending = 51
	OnboardingStatusMintFailure = 52
	OnboardingStatusMintSuccess = 53

	// 60-63 disconnect submission
	OnboardingStatusDisconnectSubmitUnknown = 60
	OnboardingStatusDisconnectSubmitPending = 61
	OnboardingStatusDisconnectSubmitFailure = 62
	OnboardingStatusDisconnectSubmitSuccess = 63

	OnboardingStatusDisconnectUnknown = 70
	OnboardingStatusDisconnectPending = 71
	OnboardingStatusDisconnectFailure = 72
	OnboardingStatusDisconnectSuccess = 73

	OnboardingStatusBurnSDUnknown = 80
	OnboardingStatusBurnSDPending = 81
	OnboardingStatusBurnSDFailure = 82
	OnboardingStatusBurnSDSuccess = 83

	// 90-93 delete submission
	OnboardingStatusDeleteSubmitUnknown = 90
	OnboardingStatusDeleteSubmitPending = 91
	OnboardingStatusDeleteSubmitFailure = 92
	OnboardingStatusDeleteSubmitSuccess = 93

	// 100-103 vehicle burn
	OnboardingStatusBurnVehicleUnknown = 100
	OnboardingStatusBurnVehiclePending = 101
	OnboardingStatusBurnVehicleFailure = 102
	OnboardingStatusBurnVehicleSuccess = 103
)

var statusToString = map[int]string{
	OnboardingStatusSubmitUnknown:           "VerificationSubmitUnknown",
	OnboardingStatusSubmitPending:           "VerificationSubmitPending",
	OnboardingStatusSubmitFailure:           "VerificationSubmitFailure",
	OnboardingStatusSubmitSuccess:           "VerificationSubmitSuccess",
	OnboardingStatusDecodingUnknown:         "DecodingUnknown",
	OnboardingStatusDecodingPending:         "DecodingPending",
	OnboardingStatusDecodingFailure:         "DecodingFailure",
	OnboardingStatusDecodingSuccess:         "DecodingSuccess",
	OnboardingStatusVendorValidationUnknown: "VendorValidationUnknown",
	OnboardingStatusVendorValidationPending: "VendorValidationPending",
	OnboardingStatusVendorValidationFailure: "VendorValidationFailure",
	OnboardingStatusVendorValidationSuccess: "VendorValidationSuccess",
	OnboardingStatusMintSubmitUnknown:       "MintSubmitUnknown",
	OnboardingStatusMintSubmitPending:       "MintSubmitPending",
	OnboardingStatusMintSubmitFailure:       "MintSubmitFailure",
	OnboardingStatusMintSubmitSuccess:       "MintSubmitSuccess",
	OnboardingStatusConnectUnknown:          "ConnectUnknown",
	OnboardingStatusConnectPending:          "ConnectPending",
	OnboardingStatusConnectFailure:          "ConnectFailure",
	OnboardingStatusConnectSuccess:          "ConnectSuccess",
	OnboardingStatusMintUnknown:             "MintUnknown",
	OnboardingStatusMintPending:             "MintPending",
	OnboardingStatusMintFailure:             "MintFailure",
	OnboardingStatusMintSuccess:             "MintSuccess",
	OnboardingStatusDisconnectSubmitUnknown: "DisconnectSubmitUnknown",
	OnboardingStatusDisconnectSubmitPending: "DisconnectSubmitPending",
	OnboardingStatusDisconnectSubmitFailure: "DisconnectSubmitFailure",
	OnboardingStatusDisconnectSubmitSuccess: "DisconnectSubmitSuccess",
	OnboardingStatusDisconnectUnknown:       "DisconnectUnknown",
	OnboardingStatusDisconnectPending:       "DisconnectPending",
	OnboardingStatusDisconnectFailure:       "DisconnectFailure",
	OnboardingStatusDisconnectSuccess:       "DisconnectSuccess",
	OnboardingStatusBurnSDUnknown:           "BurnSDUnknown",
	OnboardingStatusBurnSDPending:           "BurnSDPending",
	OnboardingStatusBurnSDFailure:           "BurnSDFailure",
	OnboardingStatusBurnSDSuccess:           "BurnSDSuccess",
	OnboardingStatusDeleteSubmitUnknown:     "DeleteSubmitUnknown",
	OnboardingStatusDeleteSubmitPending:     "DeleteSubmitPending",
	OnboardingStatusDeleteSubmitFailure:     "DeleteSubmitFailure",
	OnboardingStatusDeleteSubmitSuccess:     "DeleteSubmitSuccess",
	OnboardingStatusBurnVehicleUnknown:      "BurnVehicleUnknown",
	OnboardingStatusBurnVehiclePending:      "BurnVehiclePending",
	OnboardingStatusBurnVehicleFailure:      "BurnVehicleFailure",
	OnboardingStatusBurnVehicleSuccess:      "BurnVehicleSuccess",
}

func IsVerified(status int) bool {
	return status >= OnboardingStatusVendorValidationSuccess
}

func IsMinted(status int) bool {
	return status == OnboardingStatusMintSuccess
}

func IsDisconnected(status int) bool {
	return status == OnboardingStatusBurnSDSuccess
}

func IsFailure(status int) bool {
	return status%10 == 2
}

func IsPending(status int) bool {
	return status > 0 && status < OnboardingStatusMintSuccess
}

func IsMintPending(status int) bool {
	return status > OnboardingStatusMintSubmitUnknown && status < OnboardingStatusMintSuccess
}

func IsDisconnectPending(status int) bool {
	return (status > OnboardingStatusDisconnectSubmitUnknown && status < OnboardingStatusBurnSDSuccess) && !IsFailure(status)
}

func IsDisconnectFailed(status int) bool {
	return status == OnboardingStatusDisconnectSubmitFailure || status == OnboardingStatusBurnSDFailure || status == OnboardingStatusDisconnectFailure
}

func IsBurnPending(status int) bool {
	return status > OnboardingStatusDeleteSubmitUnknown && status < OnboardingStatusBurnVehicleSuccess
}

func GetVerificationStatus(status int) string {
	if IsVerified(status) {
		return "Success"
	}

	if IsFailure(status) {
		return "Failure"
	}

	if IsPending(status) {
		return "Pending"
	}

	return "Unknown"
}

func GetMintStatus(status int) string {
	if status == OnboardingStatusMintSuccess {
		return "Success"
	}

	if IsFailure(status) {
		return "Failure"
	}

	if IsPending(status) {
		return "Pending"
	}

	return "Unknown"
}

func GetDisconnectStatus(status int) string {
	if status == OnboardingStatusBurnSDSuccess {
		return "Success"
	}

	if IsFailure(status) {
		return "Failure"
	}

	if IsDisconnectPending(status) {
		return "Pending"
	}

	return "Unknown"
}

func GetBurnStatus(status int) string {
	if status == OnboardingStatusBurnVehicleSuccess {
		return "Success"
	}

	if IsFailure(status) {
		return "Failure"
	}

	if IsBurnPending(status) {
		return "Pending"
	}

	return "Unknown"
}

func GetDetailedStatus(status int) string {
	detailedStatus, ok := statusToString[status]
	if !ok {
		return "Unknown"
	}

	return detailedStatus
}
