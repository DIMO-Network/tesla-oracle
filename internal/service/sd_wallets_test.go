package service

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

const sdWalletsSeed = "cabaabd8c7c7d27347349e48fb11319bc6656cb6cc1bdc717e94dae8db7e6bc2"

type SDWalletsServiceTestSuite struct {
	suite.Suite
	ctx context.Context
	ws  *SDWalletsService
}

func (s *SDWalletsServiceTestSuite) SetupSuite() {
	s.ctx = context.Background()
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
	s.ws = NewSDWalletsService(s.ctx, logger, config.Settings{SDWalletsSeed: sdWalletsSeed})
}

func TestSDWalletsServiceTestSuite(t *testing.T) {
	suite.Run(t, new(SDWalletsServiceTestSuite))
}

func (s *SDWalletsServiceTestSuite) TestGetAddress() {
	addresses := [5][]common.Address{
		make([]common.Address, 0, 200),
		make([]common.Address, 0, 200),
		make([]common.Address, 0, 200),
		make([]common.Address, 0, 200),
		make([]common.Address, 0, 200),
	}

	// Generate 5 sets of addresses
	for i := 0; i < 1000; i++ {
		arrayIndex := i % 5
		address, err := s.ws.GetAddress(uint32(arrayIndex))
		s.Require().NoError(err)
		addresses[arrayIndex] = append(addresses[arrayIndex], address)
	}

	// Check if all addresses in each of the sets are the same
	for i := 0; i < 5; i++ {
		s.Require().Len(addresses[i], 200)

		for j := 1; j < 200; j++ {
			s.Require().Equal(addresses[i][0], addresses[i][j])
		}
	}
}

func (s *SDWalletsServiceTestSuite) TestHashSign() {
	addresses := [5]common.Address{}
	hashes := [5][]common.Hash{
		make([]common.Hash, 0, 200),
		make([]common.Hash, 0, 200),
		make([]common.Hash, 0, 200),
		make([]common.Hash, 0, 200),
		make([]common.Hash, 0, 200),
	}

	signatures := [5][][]byte{
		make([][]byte, 0, 200),
		make([][]byte, 0, 200),
		make([][]byte, 0, 200),
		make([][]byte, 0, 200),
		make([][]byte, 0, 200),
	}

	// Generate addresses
	for i := 0; i < 5; i++ {
		address, err := s.ws.GetAddress(uint32(i))
		s.Require().NoError(err)
		addresses[i] = address
	}

	// Generate message hashes
	for i := 0; i < 1000; i++ {
		arrayIndex := i % 5
		message := fmt.Sprintf("test message %d", i)
		hash := crypto.Keccak256([]byte(message))
		hashes[arrayIndex] = append(hashes[arrayIndex], common.BytesToHash(hash))
		signature, err := s.ws.SignHash(hash, uint32(arrayIndex))
		s.Require().NoError(err)
		signatures[arrayIndex] = append(signatures[arrayIndex], signature)
	}

	for i := 0; i < 5; i++ {
		address, err := s.ws.GetAddress(uint32(i))
		s.Require().NoError(err)
		s.Require().Equal(addresses[i], address)
		s.Require().Len(hashes[i], 200)
		s.Require().Len(signatures[i], 200)

		for j := 0; j < 200; j++ {
			index := j*5 + i

			message := fmt.Sprintf("test message %d", index)
			hash := crypto.Keccak256([]byte(message))
			s.Require().Equal(hashes[i][j], common.BytesToHash(hash))

			signature := signatures[i][j]
			signature[64] -= 27
			pubKey, err := crypto.SigToPub(hash, signature)
			s.Require().NoError(err)
			derivedAddress := crypto.PubkeyToAddress(*pubKey)
			s.Require().NoError(err)
			s.Require().Equal(derivedAddress, address)
		}
	}
}
