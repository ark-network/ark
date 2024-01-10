package main

import (
	"bytes"
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/noah/pkg/bufferutil"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
)

const minRelayFee = 400

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
	vtxoInput    *psetv2.InputArgs
	sweepTapLeaf *taproot.TapElementsLeaf
	internalKey  *secp256k1.PublicKey
}

func newRedeemBranch(ctx *cli.Context, client arkv1.ArkServiceClient, vtxo vtxo) (RedeemBranch, error) {
	round, err := client.GetRound(ctx.Context, &arkv1.GetRoundRequest{
		Txid: vtxo.poolTxid,
	})

	if err != nil {
		return nil, err
	}

	tree := round.GetRound().GetCongestionTree()

	// find vtxo
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
				keyBytes := append([]byte{0x02}, xOnlyKey...)
				internalKey, err := schnorr.ParsePubKey(keyBytes)
				if err != nil {
					return nil, err
				}

				return &redeemBranch{
					vtxo:         &vtxo,
					branch:       branch,
					vtxoInput:    nil,
					sweepTapLeaf: sweepTapLeaf,
					internalKey:  internalKey,
				}, nil

			}
		}
	}

	return nil, fmt.Errorf("vtxo not found")
}

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

func (r *redeemBranch) RedeemPath() ([]string, error) {
	transactions := make([]string, 0, len(r.branch))

	for _, pset := range r.branch {
		for i, input := range pset.Inputs {
			foundUnrollingLeaf := false

			if len(input.TapLeafScript) > 0 {
				for _, leaf := range input.TapLeafScript {
					if !bytes.Contains(leaf.Script, []byte{0xcf}) || !bytes.Contains(leaf.Script, []byte{0xd1}) {
						continue
					}

					controlBlock, err := leaf.ControlBlock.ToBytes()
					if err != nil {
						return nil, err
					}

					key := leaf.ControlBlock.InternalKey
					rootHash := leaf.ControlBlock.RootHash(leaf.Script)

					outputScript := taproot.ComputeTaprootOutputKey(key, rootHash)
					previousScriptKey := input.WitnessUtxo.Script[2:]
					if !bytes.Equal(schnorr.SerializePubKey(outputScript), previousScriptKey) {
						return nil, fmt.Errorf("invalid taproot script")
					}

					vector := [][]byte{
						leaf.Script,
						controlBlock[:],
					}

					// encode vector
					witness, err := writeTxWitness(vector)
					if err != nil {
						return nil, err
					}

					pset.Inputs[i].FinalScriptWitness = witness
					break
				}
			}

			if !foundUnrollingLeaf {
				return nil, fmt.Errorf("unrolling leaf not found on input #%d", i)
			}
		}

		// extract

		tx, err := psetv2.Extract(pset)
		if err != nil {
			return nil, err
		}

		hex, err := tx.ToHex()
		if err != nil {
			return nil, err
		}

		transactions = append(transactions, hex)
	}

	return transactions, nil
}

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
	checksigLeaf, err := checksigTapLeafScript(walletPubkey)
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

func (r *redeemBranch) rename(oldTxid string, newTxID string) error {
	newTxHash, err := chainhash.NewHashFromStr(newTxID)
	if err != nil {
		return err
	}

	for _, pset := range r.branch {
		for i, input := range pset.Inputs {
			txHash, err := chainhash.NewHash(input.PreviousTxid)
			if err != nil {
				return err
			}

			if txHash.String() == oldTxid {
				pset.Inputs[i].PreviousTxid = newTxHash.CloneBytes()
			}

		}
	}

	return nil
}

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

func writeTxWitness(wit [][]byte) ([]byte, error) {
	s := bufferutil.NewSerializer(nil)

	if err := s.WriteVector(wit); err != nil {
		return nil, err
	}
	return s.Bytes(), nil
}
