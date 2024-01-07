package main

import (
	"bytes"
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
)

type RedeemBranch interface {
	Redeem(feesCoins []psetv2.InputArgs, feeCoinsAmount uint64, changeAddr string) ([]*psetv2.Pset, []psetv2.InputArgs, error)
	EstimateFees() (uint64, error)
	VtxoInput() psetv2.InputArgs
	SweepTapLeaf() *taproot.TapElementsLeaf
	InternalTaprootKey() *secp256k1.PublicKey
	UpdateBranch() error
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

func (r *redeemBranch) InternalTaprootKey() *secp256k1.PublicKey {
	return r.internalKey
}

func (r *redeemBranch) SweepTapLeaf() *taproot.TapElementsLeaf {
	return r.sweepTapLeaf
}

func (r *redeemBranch) VtxoInput() psetv2.InputArgs {
	if r.vtxoInput == nil {
		return psetv2.InputArgs{}
	}
	return *r.vtxoInput
}

func (r *redeemBranch) UpdateBranch() error {
	_, liquidNet, err := getNetwork()
	if err != nil {
		return err
	}

	// reverse iteration
	for i := len(r.branch) - 1; i >= 0; i-- {
		pset := r.branch[i]
		for _, output := range pset.Outputs {
			pay, err := payment.FromScript(output.Script, liquidNet, nil)
			if err != nil {
				return err
			}

			addr, err := pay.TaprootAddress()
			if err != nil {
				return err
			}

			utxos, err := getOnchainUtxos(addr)
			if err != nil {
				return err
			}

			if len(utxos) > 0 {
				utx, _ := pset.UnsignedTx()
				txid := utx.TxHash().String()

				utxo := utxos[0]

				if err := r.rename(txid, utxo.Txid); err != nil {
					return err
				}

				if i+1 >= len(r.branch) {
					r.vtxoInput = &psetv2.InputArgs{
						Txid:    utxo.Txid,
						TxIndex: utxo.Vout,
					}

					r.branch = []*psetv2.Pset{}
				} else {
					r.branch = r.branch[i+1:]
				}
				return nil
			}
		}
	}

	return nil
}

func (r *redeemBranch) Redeem(feesCoins []psetv2.InputArgs, feeCoinsAmount uint64, changeAddr string) ([]*psetv2.Pset, []psetv2.InputArgs, error) {
	if len(r.branch) == 0 {
		return []*psetv2.Pset{}, feesCoins, nil
	}

	changeScript, err := address.ToOutputScript(changeAddr)
	if err != nil {
		return nil, nil, err
	}

	change, err := r.addFee(0, feesCoins, feeCoinsAmount, 400, changeScript)
	if err != nil {
		return nil, nil, err
	}

	for i := range r.branch[1:] {
		if change == nil {
			return nil, nil, fmt.Errorf("change is nil")
		}

		change, err = r.addFee(i+1, []psetv2.InputArgs{*change}, feeCoinsAmount-400*(uint64(i)+1), 400, changeScript)
		if err != nil {
			return nil, nil, err
		}
	}

	plugInInputs := make([]psetv2.InputArgs, 0, 2)

	utx, err := r.branch[len(r.branch)-1].UnsignedTx()
	if err != nil {
		return nil, nil, err
	}

	r.vtxoInput = &psetv2.InputArgs{
		Txid:    utx.TxHash().String(),
		TxIndex: 0,
	}

	if change != nil {
		plugInInputs = append(plugInInputs, *change)
	}

	return r.branch, plugInInputs, nil
}

func (r *redeemBranch) EstimateFees() (uint64, error) {
	return 400 * uint64(len(r.branch)), nil
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

func (r *redeemBranch) addFee(index int, inputs []psetv2.InputArgs, amount uint64, fee uint64, changeScript []byte) (*psetv2.InputArgs, error) {
	if index >= len(r.branch) {
		return nil, fmt.Errorf("index out of range")
	}

	pset := r.branch[index]
	utx, err := pset.UnsignedTx()
	if err != nil {
		return nil, err
	}

	oldTxid := utx.TxHash().String()

	fmt.Println("add fee to: ", oldTxid)

	_, net, err := getNetwork()
	if err != nil {
		return nil, err
	}

	asset := net.AssetID

	updater, err := psetv2.NewUpdater(pset)
	if err != nil {
		return nil, err
	}

	if err := updater.AddInputs(inputs); err != nil {
		return nil, err
	}

	if err := updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  asset,
			Amount: fee,
		},
	}); err != nil {
		return nil, err
	}

	if amount-fee > 0 {
		if err := updater.AddOutputs([]psetv2.OutputArgs{
			{
				Asset:  asset,
				Amount: amount - fee,
				Script: changeScript,
			},
		}); err != nil {
			return nil, err
		}
	}

	r.branch[index] = updater.Pset

	utx, err = updater.Pset.UnsignedTx()
	if err != nil {
		return nil, err
	}

	if err := r.rename(oldTxid, utx.TxHash().String()); err != nil {
		return nil, err
	}

	if amount-fee > 0 {
		return &psetv2.InputArgs{
			Txid:    utx.TxHash().String(),
			TxIndex: uint32(len(utx.Outputs) - 1),
		}, nil
	}

	return nil, nil
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
