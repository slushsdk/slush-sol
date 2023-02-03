package version

import (
	"encoding/binary"

	"github.com/tendermint/tendermint/crypto/tmhash"
	tmversion "github.com/tendermint/tendermint/proto/tendermint/version"
)

var (
	TMVersion = TMVersionDefault
)

const (

	// TMVersionDefault is the used as the fallback version of Tendermint Core
	// when not using git describe. It is formatted with semantic versioning.
	TMVersionDefault = "0.35.8"

	// ABCISemVer is the semantic version of the ABCI library
	ABCISemVer = "0.17.0"

	ABCIVersion = ABCISemVer
)

var (
	// P2PProtocol versions all p2p behavior and msgs.
	// This includes proposer selection.
	P2PProtocol uint64 = 8

	// BlockProtocol versions all block data structures and processing.
	// This includes validity of blocks and state updates.
	BlockProtocol uint64 = 11
)

type Consensus struct {
	Block uint64 `json:"block"`
	App   uint64 `json:"app"`
}

func (c Consensus) ToProto() tmversion.Consensus {
	return tmversion.Consensus{
		Block: c.Block,
		App:   c.App,
	}
}

func (c Consensus) Hash() []byte {

	blockByte := make([]byte, 8)
	binary.BigEndian.PutUint64(blockByte, uint64(c.Block))

	appByte := make([]byte, 8)
	binary.BigEndian.PutUint64(appByte, uint64(c.App))

	// TODO (maybe rounding ?)
	cByte := append(blockByte, appByte...)

	return tmhash.Sum(cByte)
}
