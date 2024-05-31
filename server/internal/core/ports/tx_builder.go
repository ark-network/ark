package ports

import (
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type SweepInput interface {
	GetAmount() uint64
	GetHash() chainhash.Hash
	GetIndex() uint32
	GetLeafScript() []byte
	GetControlBlock() []byte
	GetInternalKey() *secp256k1.PublicKey
}

type TxBuilder interface {
	BuildPoolTx(aspPubkey *secp256k1.PublicKey, payments []domain.Payment, minRelayFee uint64, sweptRounds []domain.Round) (poolTx string, congestionTree tree.CongestionTree, connectorAddress string, err error)
	BuildForfeitTxs(aspPubkey *secp256k1.PublicKey, poolTx string, payments []domain.Payment, minRelayFee uint64) (connectors []string, forfeitTxs []string, err error)
	BuildSweepTx(inputs []SweepInput) (signedSweepTx string, err error)
	GetVtxoScript(userPubkey, aspPubkey *secp256k1.PublicKey) ([]byte, error)
	GetSweepInput(parentblocktime int64, node tree.Node) (expirationtime int64, sweepInput SweepInput, err error)
}
