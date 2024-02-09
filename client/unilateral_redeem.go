package main

import (
	"fmt"

	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
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
	internalKey  *secp256k1.PublicKey
	sweepClosure *taproot.TapElementsLeaf
}

func newRedeemBranch(ctx *cli.Context, congestionTree tree.CongestionTree, vtxo vtxo) (RedeemBranch, error) {
	sweepClosure, _, err := findSweepClosure(congestionTree)
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
	}, nil
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

			for _, leaf := range input.TapLeafScript {
				isSweep, _, _, err := tree.DecodeSweepScript(leaf.Script)
				if err != nil {
					return nil, err
				}

				if isSweep {
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
		*r.sweepClosure,
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
