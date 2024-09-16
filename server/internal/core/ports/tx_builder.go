package ports

import (
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
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

type BoardingInput interface {
	GetAmount() uint64
	GetIndex() uint32
	GetHash() chainhash.Hash
	GetBoardingPubkey() *secp256k1.PublicKey
}

type TxBuilder interface {
	BuildPoolTx(
		aspPubkey *secp256k1.PublicKey, payments []domain.Payment, boardingInputs []BoardingInput, sweptRounds []domain.Round,
		cosigners ...*secp256k1.PublicKey,
	) (poolTx string, congestionTree tree.CongestionTree, connectorAddress string, err error)
	BuildForfeitTxs(aspPubkey *secp256k1.PublicKey, poolTx string, payments []domain.Payment) (connectors []string, forfeitTxs []string, err error)
	BuildSweepTx(inputs []SweepInput) (signedSweepTx string, err error)
	GetVtxoScript(userPubkey, aspPubkey *secp256k1.PublicKey) ([]byte, error)
	GetSweepInput(parentblocktime int64, node tree.Node) (expirationtime int64, sweepInput SweepInput, err error)
	FinalizeAndExtract(tx string) (txhex string, err error)
	VerifyTapscriptPartialSigs(tx string) (valid bool, txid string, err error)
	// FindLeaves returns all the leaves txs that are reachable from the given outpoint
	FindLeaves(congestionTree tree.CongestionTree, fromtxid string, vout uint32) (leaves []tree.Node, err error)
	BuildAsyncPaymentTransactions(
		vtxosToSpend []domain.Vtxo,
		aspPubKey *secp256k1.PublicKey, receivers []domain.Receiver,
	) (*domain.AsyncPaymentTxs, error)
	GetBoardingScript(userPubkey, aspPubkey *secp256k1.PublicKey) (addr string, script []byte, err error)
	VerifyAndCombinePartialTx(dest string, src string) (string, error)
}
