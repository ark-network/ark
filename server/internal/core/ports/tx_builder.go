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

type Input struct {
	domain.VtxoKey
	Tapscripts []string
}

type BoardingInput struct {
	Input
	Amount uint64
}

type TxBuilder interface {
	// BuildRoundTx builds a round tx for the given payments, boarding inputs
	// it selects coin from swept rounds and ASP wallet
	// returns the round partial tx, the vtxo tree and the set of connectors
	BuildRoundTx(
		aspPubkey *secp256k1.PublicKey, payments []domain.Payment, boardingInputs []BoardingInput, sweptRounds []domain.Round,
		cosigners ...*secp256k1.PublicKey,
	) (
		roundTx string,
		congestionTree tree.CongestionTree,
		connectorAddress string,
		connectors []string,
		err error,
	)
	// VerifyForfeitTxs verifies the given forfeit txs for the given vtxos and connectors
	VerifyForfeitTxs(
		vtxos []domain.Vtxo,
		connectors []string,
		txs []string,
	) (valid map[domain.VtxoKey][]string, err error)
	BuildSweepTx(inputs []SweepInput) (signedSweepTx string, err error)
	GetSweepInput(node tree.Node) (lifetime int64, sweepInput SweepInput, err error)
	FinalizeAndExtract(tx string) (txhex string, err error)
	VerifyTapscriptPartialSigs(tx string) (valid bool, err error)
	// FindLeaves returns all the leaves txs that are reachable from the given outpoint
	FindLeaves(congestionTree tree.CongestionTree, fromtxid string, vout uint32) (leaves []tree.Node, err error)
	BuildAsyncPaymentTransactions(
		vtxosToSpend []domain.Vtxo,
		scripts map[domain.VtxoKey][]string,
		forfeitsLeaves map[domain.VtxoKey]chainhash.Hash,
		receivers []domain.Receiver,
	) (string, error)
	VerifyAndCombinePartialTx(dest string, src string) (string, error)
	GetTxID(tx string) (string, error)
}
