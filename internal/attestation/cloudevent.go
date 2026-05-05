package attestation

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
)

const EventTypeDeviceDefinition = "dimo.document.devicedefinition"

func NewSignedEvent(subject, source, eventType string, data json.RawMessage, privateKey *ecdsa.PrivateKey) (*cloudevent.RawEvent, error) {
	signature, err := SignERC191(data, privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign event payload: %w", err)
	}

	return &cloudevent.RawEvent{
		CloudEventHeader: cloudevent.CloudEventHeader{
			ID:              uuid.NewString(),
			Source:          source,
			Producer:        source,
			SpecVersion:     cloudevent.SpecVersion,
			Subject:         subject,
			Time:            time.Now().UTC(),
			Type:            eventType,
			DataContentType: "application/json",
			Signature:       signature,
		},
		Data: data,
	}, nil
}

func SignERC191[T ~[]byte | ~string](message T, privateKey *ecdsa.PrivateKey) (string, error) {
	prefixed := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	hash := crypto.Keccak256Hash([]byte(prefixed))
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return "", err
	}

	signature[64] += 27
	return "0x" + hex.EncodeToString(signature), nil
}
