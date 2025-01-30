package ports

import (
	"github.com/ark-network/ark/common"
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
	// BuildRoundTx builds a round tx for the given offchain and boarding tx
	// requests. It expects an optional list of connector addresses of expired
	// rounds from which selecting UTXOs as inputs of the transaction.
	// Returns the round tx, the VTXO tree, the connector chain and its root
	// address.
	BuildRoundTx(
		serverPubkey *secp256k1.PublicKey, txRequests []domain.TxRequest,
		boardingInputs []BoardingInput, connectorAddresses []string,
		musig2Data []*tree.Musig2, // only for covenantless
	) (
		roundTx string,
		vtxoTree tree.VtxoTree,
		connectorAddress string,
		connectors []string,
		err error,
	)
	// VerifyForfeitTxs verifies a list of forfeit txs against a set of VTXOs and
	// connectors.
	VerifyForfeitTxs(
		vtxos []domain.Vtxo, connectors []string, txs []string,
	) (valid map[domain.VtxoKey][]string, err error)
	BuildSweepTx(inputs []SweepInput) (signedSweepTx string, err error)
	GetSweepInput(node tree.Node) (vtxoTreeExpiry *common.RelativeLocktime, sweepInput SweepInput, err error)
	FinalizeAndExtract(tx string) (txhex string, err error)
	VerifyTapscriptPartialSigs(tx string) (valid bool, err error)
	// FindLeaves returns all the leaves txs that are reachable from the given outpoint
	FindLeaves(vtxoTree tree.VtxoTree, fromtxid string, vout uint32) (leaves []tree.Node, err error)
	VerifyAndCombinePartialTx(dest string, src string) (string, error)
	GetTxID(tx string) (string, error)
}
