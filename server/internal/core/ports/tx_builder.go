package ports

import (
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

type SweepInput interface {
	GetAmount() uint64
	GetHash() chainhash.Hash
	GetIndex() uint32
	GetLeafScript() []byte
	GetControlBlock() []byte
	GetInternalKey() *secp256k1.PublicKey
}

type Input struct {
	domain.VtxoKey
	Descriptor string
}

type BoardingInput struct {
	Input
	Amount uint64
}

type TxBuilder interface {
	BuildRoundTx(
		aspPubkey *secp256k1.PublicKey, payments []domain.Payment, boardingInputs []BoardingInput, sweptRounds []domain.Round,
		cosigners ...*secp256k1.PublicKey,
	) (roundTx string, congestionTree tree.CongestionTree, connectorAddress string, err error)
	BuildForfeitTxs(poolTx string, payments []domain.Payment, minRelayFeeRate chainfee.SatPerKVByte) (connectors []string, forfeitTxs []string, err error)
	BuildSweepTx(inputs []SweepInput) (signedSweepTx string, err error)
	GetSweepInput(node tree.Node) (lifetime int64, sweepInput SweepInput, err error)
	FinalizeAndExtract(tx string) (txhex string, err error)
	VerifyTapscriptPartialSigs(tx string) (valid bool, txid string, err error)
	// FindLeaves returns all the leaves txs that are reachable from the given outpoint
	FindLeaves(congestionTree tree.CongestionTree, fromtxid string, vout uint32) (leaves []tree.Node, err error)
	BuildAsyncPaymentTransactions(
		vtxosToSpend []domain.Vtxo,
		aspPubKey *secp256k1.PublicKey, receivers []domain.Receiver,
	) (string, error)
	VerifyAndCombinePartialTx(dest string, src string) (string, error)
	GetTxID(tx string) (string, error)
}
