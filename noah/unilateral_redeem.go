package main

import (
	"bytes"
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/pkg/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
)

type RedeemBranch interface {
	// UpdatePath checks for transactions of the branch onchain and updates the branch accordingly
	UpdatePath() error
	// Redeem will sign the branch of the tree and return the associated signed pset + the vtxo input
	RedeemPath() ([]string, error)
	// AddInput adds the vtxo input created by the branch
	AddVtxoInput(updater *psetv2.Updater) error
}

type redeemBranch struct {
	vtxo         *vtxo
	branch       []*psetv2.Pset
	sweepTapLeaf *taproot.TapElementsLeaf
	internalKey  *secp256k1.PublicKey
}

func newRedeemBranch(ctx *cli.Context, tree *arkv1.Tree, vtxo vtxo) (RedeemBranch, error) {
	for _, level := range tree.Levels {
		for _, node := range level.Nodes {
			if node.Txid == vtxo.txid {
				nodes, err := findParents([]*arkv1.Node{node}, tree)
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

				// find sweep tap leaf
				sweepTapLeaf, err := findSweepLeafScript(branch[0].Inputs[0].TapLeafScript)
				if err != nil {
					return nil, err
				}

				xOnlyKey := branch[0].Inputs[0].TapInternalKey
				internalKey, err := schnorr.ParsePubKey(xOnlyKey)
				if err != nil {
					return nil, err
				}

				return &redeemBranch{
					vtxo:         &vtxo,
					branch:       branch,
					sweepTapLeaf: sweepTapLeaf,
					internalKey:  internalKey,
				}, nil

			}
		}
	}

	return nil, fmt.Errorf("vtxo not found")
}

// UpdatePath checks for transactions of the branch onchain and updates the branch accordingly
func (r *redeemBranch) UpdatePath() error {
	for i := len(r.branch) - 1; i >= 0; i-- {
		pset := r.branch[i]
		unsignedTx, err := pset.UnsignedTx()
		if err != nil {
			return err
		}

		txHash := unsignedTx.TxHash().String()

		_, err = getTxHex(txHash)
		if err != nil {
			continue
		}

		// if no error, the tx exists onchain, so we can remove it (+ the parents) from the branch
		if i == len(r.branch)-1 {
			r.branch = []*psetv2.Pset{}
		} else {
			r.branch = r.branch[i+1:]
		}

		break
	}

	return nil
}

// RedeemPath returns the list of transactions to broadcast in order to access the vtxo output
func (r *redeemBranch) RedeemPath() ([]string, error) {
	transactions := make([]string, 0, len(r.branch))

	for _, pset := range r.branch {
		for i, input := range pset.Inputs {
			if len(input.TapLeafScript) == 0 {
				return nil, fmt.Errorf("tap leaf script not found on input #%d", i)
			}

			sweepTapLeafScript := r.sweepTapLeaf.Script

			for _, leaf := range input.TapLeafScript {
				if bytes.Equal(leaf.Script, sweepTapLeafScript) {
					continue
				}

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

				break
			}

		}

	}

	return transactions, nil
}

// AddVtxoInput is a wrapper around psetv2.Updater adding a taproot input letting to spend the vtxo output
func (r *redeemBranch) AddVtxoInput(updater *psetv2.Updater) error {
	walletPubkey, err := getWalletPublicKey()
	if err != nil {
		return err
	}

	nextInputIndex := len(updater.Pset.Inputs)
	if err := updater.AddInputs([]psetv2.InputArgs{
		{
			Txid:    r.vtxo.txid,
			TxIndex: r.vtxo.vout,
		},
	}); err != nil {
		return err
	}

	// add taproot tree letting to spend the vtxo
	checksigLeaf, err := tree.VtxoScript(walletPubkey)
	if err != nil {
		return nil
	}

	vtxoTaprootTree := taproot.AssembleTaprootScriptTree(
		*checksigLeaf,
		*r.sweepTapLeaf,
	)

	proofIndex := vtxoTaprootTree.LeafProofIndex[checksigLeaf.TapHash()]

	if err := updater.AddInTapLeafScript(
		nextInputIndex,
		psetv2.NewTapLeafScript(
			vtxoTaprootTree.LeafMerkleProofs[proofIndex],
			r.internalKey,
		),
	); err != nil {
		return err
	}

	return nil
}

// findParents is a recursive function that finds all the parents of a VTXO in a congestion tree
// it returns the branch of the tree letting to redeem the VTXO (from pool tx to leaf)
func findParents(ls []*arkv1.Node, tree *arkv1.Tree) ([]*arkv1.Node, error) {
	if len(ls) == 0 {
		return nil, fmt.Errorf("empty list")
	}

	for levelIndex, level := range tree.Levels {
		for _, node := range level.Nodes {
			if node.Txid == ls[0].ParentTxid {
				newTree := &arkv1.Tree{
					Levels: tree.Levels[:levelIndex],
				}

				newList := append([]*arkv1.Node{node}, ls...)
				if len(newTree.Levels) > 0 {
					return findParents(newList, newTree)
				}

				return newList, nil
			}
		}
	}
	return nil, fmt.Errorf("parent not found")
}

// findSweepLeafScript finds the sweep leaf in a set of tap leaf scripts
func findSweepLeafScript(leaves []psetv2.TapLeafScript) (*taproot.TapElementsLeaf, error) {
	for _, leaf := range leaves {
		if len(leaf.Script) == 0 {
			continue
		}

		if bytes.Contains(leaf.Script, []byte{txscript.OP_CHECKSIG}) && bytes.Contains(leaf.Script, []byte{txscript.OP_CHECKSEQUENCEVERIFY}) {
			tapLeaf := taproot.NewBaseTapElementsLeaf(leaf.Script)
			return &tapLeaf, nil
		}

	}
	return nil, fmt.Errorf("sweep leaf not found")
}
