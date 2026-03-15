package telemetry

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DIMO-Network/cloudevent"
	"github.com/ethereum/go-ethereum/common"
	signer "github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type stubSender struct {
	payloads [][]byte
	err      error
}

func (s *stubSender) Send(ctx context.Context, data []byte) error {
	if s.err != nil {
		return s.err
	}
	s.payloads = append(s.payloads, data)
	return nil
}

type stubWallet struct{}

func (s *stubWallet) GetAddress(ctx context.Context, index uint32) (common.Address, error) {
	return common.Address{}, nil
}

func (s *stubWallet) SignHash(ctx context.Context, hash []byte, index uint32) ([]byte, error) {
	sig := make([]byte, 65)
	copy(sig, hash)
	sig[64] = 27
	return sig, nil
}

func (s *stubWallet) SignTypedData(ctx context.Context, data signer.TypedData, index uint32) ([]byte, error) {
	return nil, nil
}

func TestBatcherBatchesByVehicleTokenAndSignsPayload(t *testing.T) {
	logger := zerolog.Nop()
	sender := &stubSender{}
	batcher := NewBatcher(
		sender,
		&stubWallet{},
		common.HexToAddress("0x45fbCD3ef7361d156e8b16F5538AE36DEdf61Da8"),
		common.HexToAddress("0x78513c8CB4D6B6079f813850376bc9c7fc8aE67f"),
		"0xc4035Fecb1cc906130423EF05f9C20977F643722",
		80002,
		&logger,
	)

	batcher.Add(VehicleMetadata{
		synthDevices: []syntheticDeviceMetadata{
			{vehicleTokenID: 100, tokenID: 200, walletChildNum: 1},
		},
		data: []byte(`{"speed":1}`),
	})
	batcher.Add(VehicleMetadata{
		synthDevices: []syntheticDeviceMetadata{
			{vehicleTokenID: 100, tokenID: 200, walletChildNum: 1},
		},
		data: []byte(`{"speed":2}`),
	})

	err := batcher.SendData(context.Background())
	require.NoError(t, err)
	require.Len(t, sender.payloads, 1)
	require.Empty(t, batcher.batchByTokenID)

	var event cloudevent.CloudEvent[json.RawMessage]
	require.NoError(t, json.Unmarshal(sender.payloads[0], &event))
	require.NotEmpty(t, event.Signature)

	var data struct {
		Payloads []json.RawMessage `json:"payloads"`
	}
	require.NoError(t, json.Unmarshal(event.Data, &data))
	require.Len(t, data.Payloads, 2)
}
