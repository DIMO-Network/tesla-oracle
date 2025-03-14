package consumer

import (
	"context"
	"encoding/json"
	"math/big"

	"github.com/DIMO-Network/shared/db"

	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"

	"github.com/stretchr/testify/suite"
)

type ProcessorTestSuite struct {
	suite.Suite
	pdb       db.Store
	logger    *zerolog.Logger
	processor *Processor
}

func (s *ProcessorTestSuite) SetupTest() {
	logger := zerolog.New(nil)
	pdb, _ := test.StartContainerDatabase(context.Background, s.T(), "../../migrations/")
	s.pdb = pdb
	s.processor = New(s.pdb, "test-topic", &logger)
}

func (s *ProcessorTestSuite) TestHandleSyntheticDeviceNodeMinted() {
	ctx := context.Background()
	deviceAddr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	ownerAddr := common.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")

	mintEvent := SyntheticDeviceNodeMinted{
		IntegrationNode:        big.NewInt(2),
		SyntheticDeviceNode:    big.NewInt(1001),
		VehicleNode:            big.NewInt(2001),
		SyntheticDeviceAddress: deviceAddr,
		Owner:                  ownerAddr,
	}

	data, err := json.Marshal(mintEvent)
	s.Require().NoError(err)

	err = s.processor.handleSyntheticDeviceNodeMinted(ctx, data)
	s.Require().NoError(err)
}

func (s *ProcessorTestSuite) TestHandleSyntheticDeviceNodeBurned() {
	ctx := context.Background()
	burnEvent := SyntheticDeviceNodeBurned{
		SyntheticDeviceNode: big.NewInt(1001),
		VehicleNode:         big.NewInt(2001),
		Owner:               common.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
	}

	data, err := json.Marshal(burnEvent)
	s.Require().NoError(err)

	err = s.processor.handleSyntheticDeviceNodeBurned(ctx, data)
	s.Require().NoError(err)
}
