package redemption

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

type CovenantlessRedeemBranch struct {
	vtxo           client.Vtxo
	branch         []*psbt.Packet
	vtxoTreeExpiry time.Duration
	explorer       explorer.Explorer
}

func NewCovenantlessRedeemBranch(
	explorer explorer.Explorer,
	vtxoTree tree.VtxoTree, vtxo client.Vtxo,
) (*CovenantlessRedeemBranch, error) {
	root, err := vtxoTree.Root()
	if err != nil {
		return nil, err
	}

	ptxRoot, err := psbt.NewFromRawBytes(strings.NewReader(root.Tx), true)
	if err != nil {
		return nil, err
	}

	vtxoTreeExpiry, err := bitcointree.GetVtxoTreeExpiry(ptxRoot.Inputs[0])
	if err != nil {
		return nil, err
	}

	nodes, err := vtxoTree.Branch(vtxo.Txid)
	if err != nil {
		return nil, err
	}

	branch := make([]*psbt.Packet, 0, len(nodes))
	for _, node := range nodes {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
		if err != nil {
			return nil, err
		}
		branch = append(branch, ptx)
	}

	return &CovenantlessRedeemBranch{
		vtxo:           vtxo,
		branch:         branch,
		vtxoTreeExpiry: time.Duration(vtxoTreeExpiry.Seconds()) * time.Second,
		explorer:       explorer,
	}, nil
}

// RedeemPath returns the list of transactions to broadcast in order to access the vtxo output
func (r *CovenantlessRedeemBranch) RedeemPath() ([]string, error) {
	transactions := make([]string, 0, len(r.branch))

	offchainPath, err := r.OffchainPath()
	if err != nil {
		return nil, err
	}

	for _, ptx := range offchainPath {
		firstInput := ptx.Inputs[0]
		if len(firstInput.TaprootKeySpendSig) == 0 {
			return nil, fmt.Errorf("missing taproot key spend signature")
		}

		var witness bytes.Buffer

		if err := psbt.WriteTxWitness(&witness, [][]byte{firstInput.TaprootKeySpendSig}); err != nil {
			return nil, err
		}

		ptx.Inputs[0].FinalScriptWitness = witness.Bytes()

		extracted, err := psbt.Extract(ptx)
		if err != nil {
			return nil, err
		}

		var txBytes bytes.Buffer

		if err := extracted.Serialize(&txBytes); err != nil {
			return nil, err
		}

		transactions = append(transactions, hex.EncodeToString(txBytes.Bytes()))
	}

	return transactions, nil
}

func (r *CovenantlessRedeemBranch) ExpiresAt() (*time.Time, error) {
	lastKnownBlocktime := int64(0)

	confirmed, blocktime, _ := r.explorer.GetTxBlockTime(r.vtxo.RoundTxid)

	if confirmed {
		lastKnownBlocktime = blocktime
	} else {
		expirationFromNow := time.Now().Add(time.Minute).Add(r.vtxoTreeExpiry)
		return &expirationFromNow, nil
	}

	for _, ptx := range r.branch {
		txid := ptx.UnsignedTx.TxHash().String()

		confirmed, blocktime, err := r.explorer.GetTxBlockTime(txid)
		if err != nil {
			break
		}

		if confirmed {
			lastKnownBlocktime = blocktime
			continue
		}

		break
	}

	t := time.Unix(lastKnownBlocktime, 0).Add(r.vtxoTreeExpiry)
	return &t, nil
}

// offchainPath checks for transactions of the branch onchain and returns only the offchain part
func (r *CovenantlessRedeemBranch) OffchainPath() ([]*psbt.Packet, error) {
	offchainPath := append([]*psbt.Packet{}, r.branch...)

	for i := len(r.branch) - 1; i >= 0; i-- {
		ptx := r.branch[i]
		txHash := ptx.UnsignedTx.TxHash().String()

		if _, err := r.explorer.GetTxHex(txHash); err != nil {
			continue
		}

		// if no error, the tx exists onchain, so we can remove it (+ the parents) from the branch
		if i == len(r.branch)-1 {
			offchainPath = []*psbt.Packet{}
		} else {
			offchainPath = r.branch[i+1:]
		}

		break
	}

	return offchainPath, nil
}
