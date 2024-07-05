package covenantless

import (
	"fmt"
	"time"

	"github.com/ark-network/ark-cli/utils"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
)

type redeemBranch struct {
	vtxo         *vtxo
	branch       []*psetv2.Pset
	internalKey  *secp256k1.PublicKey
	sweepClosure *taproot.TapElementsLeaf
	lifetime     time.Duration
	explorer     utils.Explorer
}

func newRedeemBranch(
	explorer utils.Explorer,
	congestionTree tree.CongestionTree, vtxo vtxo,
) (*redeemBranch, error) {
	sweepClosure, seconds, err := findSweepClosure(congestionTree)
	if err != nil {
		return nil, err
	}

	lifetime, err := time.ParseDuration(fmt.Sprintf("%ds", seconds))
	if err != nil {
		return nil, err
	}

	nodes, err := congestionTree.Branch(vtxo.txid)
	if err != nil {
		return nil, err
	}

	branch := make([]*psetv2.Pset, 0, len(nodes))
	for _, node := range nodes {
		pset, err := psetv2.NewPsetFromBase64(node.Tx)
		if err != nil {
			return nil, err
		}
		branch = append(branch, pset)
	}

	xOnlyKey := branch[0].Inputs[0].TapInternalKey
	internalKey, err := schnorr.ParsePubKey(xOnlyKey)
	if err != nil {
		return nil, err
	}

	return &redeemBranch{
		vtxo:         &vtxo,
		branch:       branch,
		internalKey:  internalKey,
		sweepClosure: sweepClosure,
		lifetime:     lifetime,
		explorer:     explorer,
	}, nil
}

// RedeemPath returns the list of transactions to broadcast in order to access the vtxo output
func (r *redeemBranch) redeemPath() ([]string, error) {
	transactions := make([]string, 0, len(r.branch))

	offchainPath, err := r.offchainPath()
	if err != nil {
		return nil, err
	}

	for _, pset := range offchainPath {
		for i, input := range pset.Inputs {
			if len(input.TapLeafScript) == 0 {
				return nil, fmt.Errorf("tap leaf script not found on input #%d", i)
			}

			for _, leaf := range input.TapLeafScript {
				closure, err := tree.DecodeClosure(leaf.Script)
				if err != nil {
					return nil, err
				}

				switch closure.(type) {
				case *tree.UnrollClosure:
					controlBlock, err := leaf.ControlBlock.ToBytes()
					if err != nil {
						return nil, err
					}

					unsignedTx, err := pset.UnsignedTx()
					if err != nil {
						return nil, err
					}

					unsignedTx.Inputs[i].Witness = [][]byte{
						leaf.Script,
						controlBlock[:],
					}

					hex, err := unsignedTx.ToHex()
					if err != nil {
						return nil, err
					}
					transactions = append(transactions, hex)
				}
			}
		}
	}

	return transactions, nil
}

func (r *redeemBranch) expireAt(*cli.Context) (*time.Time, error) {
	lastKnownBlocktime := int64(0)

	confirmed, blocktime, _ := r.explorer.GetTxBlocktime(r.vtxo.poolTxid)

	if confirmed {
		lastKnownBlocktime = blocktime
	} else {
		expirationFromNow := time.Now().Add(time.Minute).Add(r.lifetime)
		return &expirationFromNow, nil
	}

	for _, pset := range r.branch {
		utx, _ := pset.UnsignedTx()
		txid := utx.TxHash().String()

		confirmed, blocktime, err := r.explorer.GetTxBlocktime(txid)
		if err != nil {
			break
		}

		if confirmed {
			lastKnownBlocktime = blocktime
			continue
		}

		break
	}

	t := time.Unix(lastKnownBlocktime, 0).Add(r.lifetime)
	return &t, nil
}

// offchainPath checks for transactions of the branch onchain and returns only the offchain part
func (r *redeemBranch) offchainPath() ([]*psetv2.Pset, error) {
	offchainPath := append([]*psetv2.Pset{}, r.branch...)

	for i := len(r.branch) - 1; i >= 0; i-- {
		pset := r.branch[i]
		unsignedTx, err := pset.UnsignedTx()
		if err != nil {
			fmt.Println("error", err)
			return nil, err
		}

		txHash := unsignedTx.TxHash().String()

		_, err = r.explorer.GetTxHex(txHash)
		if err != nil {
			continue
		}

		// if no error, the tx exists onchain, so we can remove it (+ the parents) from the branch
		if i == len(r.branch)-1 {
			offchainPath = []*psetv2.Pset{}
		} else {
			offchainPath = r.branch[i+1:]
		}

		break
	}

	return offchainPath, nil
}

func findSweepClosure(
	congestionTree tree.CongestionTree,
) (*taproot.TapElementsLeaf, uint, error) {
	root, err := congestionTree.Root()
	if err != nil {
		return nil, 0, err
	}

	// find the sweep closure
	tx, err := psetv2.NewPsetFromBase64(root.Tx)
	if err != nil {
		return nil, 0, err
	}

	var seconds uint
	var sweepClosure *taproot.TapElementsLeaf
	for _, tapLeaf := range tx.Inputs[0].TapLeafScript {
		closure := &tree.CSVSigClosure{}
		valid, err := closure.Decode(tapLeaf.Script)
		if err != nil {
			continue
		}

		if valid && closure.Seconds > seconds {
			seconds = closure.Seconds
			sweepClosure = &tapLeaf.TapElementsLeaf
		}
	}

	if sweepClosure == nil {
		return nil, 0, fmt.Errorf("sweep closure not found")
	}

	return sweepClosure, seconds, nil
}
