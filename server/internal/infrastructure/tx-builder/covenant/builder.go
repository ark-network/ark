package txbuilder

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
)

const (
	connectorAmount = uint64(450)
	dustLimit       = uint64(450)
)

type txBuilder struct {
	wallet        ports.WalletService
	net           *network.Network
	roundLifetime int64 // in seconds
	exitDelay     int64 // in seconds
}

func NewTxBuilder(
	wallet ports.WalletService, net network.Network, roundLifetime int64, exitDelay int64,
) ports.TxBuilder {
	return &txBuilder{wallet, &net, roundLifetime, exitDelay}
}

func (b *txBuilder) GetVtxoScript(userPubkey, aspPubkey *secp256k1.PublicKey) ([]byte, error) {
	outputScript, _, err := b.getLeafScriptAndTree(userPubkey, aspPubkey)
	if err != nil {
		return nil, err
	}
	return outputScript, nil
}

func (b *txBuilder) BuildSweepTx(inputs []ports.SweepInput) (signedSweepTx string, err error) {
	sweepPset, err := sweepTransaction(
		b.wallet,
		inputs,
		b.net.AssetID,
	)
	if err != nil {
		return "", err
	}

	sweepPsetBase64, err := sweepPset.ToBase64()
	if err != nil {
		return "", err
	}

	ctx := context.Background()
	signedSweepPsetB64, err := b.wallet.SignPsetWithKey(ctx, sweepPsetBase64, nil)
	if err != nil {
		return "", err
	}

	signedPset, err := psetv2.NewPsetFromBase64(signedSweepPsetB64)
	if err != nil {
		return "", err
	}

	if err := psetv2.FinalizeAll(signedPset); err != nil {
		return "", err
	}

	extractedTx, err := psetv2.Extract(signedPset)
	if err != nil {
		return "", err
	}

	return extractedTx.ToHex()
}

func (b *txBuilder) BuildForfeitTxs(
	connectorAddress string, aspPubkey *secp256k1.PublicKey,
	poolTx string, payments []domain.Payment, minRelayFee uint64,
) (connectors []string, forfeitTxs []string, err error) {
	connectorTxs, err := b.createConnectors(poolTx, payments, connectorAddress, minRelayFee)
	if err != nil {
		return nil, nil, err
	}

	forfeitTxs, err = b.createForfeitTxs(aspPubkey, payments, connectorTxs)
	if err != nil {
		return nil, nil, err
	}

	for _, tx := range connectorTxs {
		buf, _ := tx.ToBase64()
		connectors = append(connectors, buf)
	}
	return connectors, forfeitTxs, nil
}

func (b *txBuilder) BuildPoolTx(
	connectorAddress string, aspPubkey *secp256k1.PublicKey, payments []domain.Payment, minRelayFee uint64,
) (poolTx string, congestionTree tree.CongestionTree, err error) {
	// The creation of the tree and the pool tx are tightly coupled:
	// - building the tree requires knowing the shared outpoint (txid:vout)
	// - building the pool tx requires knowing the shared output script and amount
	// The idea here is to first create all the data for the outputs of the txs
	// of the congestion tree to calculate the shared output script and amount.
	// With these data the pool tx can be created, and once the shared utxo
	// outpoint is obtained, the congestion tree can be finally created.
	// The factory function `treeFactoryFn` returned below holds all outputs data
	// generated in the process and takes the shared utxo outpoint as argument.
	// This is safe as the memory allocated for `craftCongestionTree` is freed
	// only after `BuildPoolTx` returns.
	treeFactoryFn, sharedOutputScript, sharedOutputAmount, err := craftCongestionTree(
		b.net.AssetID, aspPubkey, payments, minRelayFee, b.roundLifetime, b.exitDelay,
	)
	if err != nil {
		return
	}

	ptx, err := b.createPoolTx(
		sharedOutputAmount, sharedOutputScript, payments, aspPubkey, connectorAddress, minRelayFee,
	)
	if err != nil {
		return
	}

	unsignedTx, err := ptx.UnsignedTx()
	if err != nil {
		return
	}

	tree, err := treeFactoryFn(psetv2.InputArgs{
		Txid:    unsignedTx.TxHash().String(),
		TxIndex: 0,
	})
	if err != nil {
		return
	}

	poolTx, err = ptx.ToBase64()
	if err != nil {
		return
	}

	congestionTree = tree
	return
}

func (b *txBuilder) getLeafScriptAndTree(
	userPubkey, aspPubkey *secp256k1.PublicKey,
) ([]byte, *taproot.IndexedElementsTapScriptTree, error) {
	redeemClosure := &tree.CSVSigClosure{
		Pubkey:  userPubkey,
		Seconds: uint(b.exitDelay),
	}

	redeemLeaf, err := redeemClosure.Leaf()
	if err != nil {
		return nil, nil, err
	}

	forfeitClosure := &tree.ForfeitClosure{
		Pubkey:    userPubkey,
		AspPubkey: aspPubkey,
	}

	forfeitLeaf, err := forfeitClosure.Leaf()
	if err != nil {
		return nil, nil, err
	}

	taprootTree := taproot.AssembleTaprootScriptTree(
		*redeemLeaf, *forfeitLeaf,
	)

	root := taprootTree.RootNode.TapHash()
	unspendableKey := tree.UnspendableKey()
	taprootKey := taproot.ComputeTaprootOutputKey(unspendableKey, root[:])

	outputScript, err := taprootOutputScript(taprootKey)
	if err != nil {
		return nil, nil, err
	}

	return outputScript, taprootTree, nil
}

func (b *txBuilder) createPoolTx(
	sharedOutputAmount uint64, sharedOutputScript []byte,
	payments []domain.Payment, aspPubKey *secp256k1.PublicKey, connectorAddress string, minRelayFee uint64,
) (*psetv2.Pset, error) {
	aspScript, err := p2wpkhScript(aspPubKey, b.net)
	if err != nil {
		return nil, err
	}

	connectorScript, err := address.ToOutputScript(connectorAddress)
	if err != nil {
		return nil, err
	}

	receivers := getOnchainReceivers(payments)
	connectorsAmount := (connectorAmount+minRelayFee)*countSpentVtxos(payments) - minRelayFee
	targetAmount := sharedOutputAmount + connectorsAmount

	outputs := []psetv2.OutputArgs{
		{
			Asset:  b.net.AssetID,
			Amount: sharedOutputAmount,
			Script: sharedOutputScript,
		},
		{
			Asset:  b.net.AssetID,
			Amount: connectorsAmount,
			Script: connectorScript,
		},
	}

	for _, receiver := range receivers {
		targetAmount += receiver.Amount

		receiverScript, err := address.ToOutputScript(receiver.OnchainAddress)
		if err != nil {
			return nil, err
		}

		outputs = append(outputs, psetv2.OutputArgs{
			Asset:  b.net.AssetID,
			Amount: receiver.Amount,
			Script: receiverScript,
		})
	}

	ctx := context.Background()
	utxos, change, err := b.wallet.SelectUtxos(ctx, b.net.AssetID, targetAmount)
	if err != nil {
		return nil, err
	}

	var dust uint64
	if change > 0 {
		if change < dustLimit {
			dust = change
			change = 0
		} else {
			outputs = append(outputs, psetv2.OutputArgs{
				Asset:  b.net.AssetID,
				Amount: change,
				Script: aspScript,
			})
		}
	}

	ptx, err := psetv2.New(nil, outputs, nil)
	if err != nil {
		return nil, err
	}

	updater, err := psetv2.NewUpdater(ptx)
	if err != nil {
		return nil, err
	}

	if err := addInputs(updater, utxos); err != nil {
		return nil, err
	}

	b64, err := ptx.ToBase64()
	if err != nil {
		return nil, err
	}

	feeAmount, err := b.wallet.EstimateFees(ctx, b64)
	if err != nil {
		return nil, err
	}

	if dust > feeAmount {
		feeAmount = dust
	} else {
		feeAmount += dust
	}

	if dust == 0 {
		if feeAmount == change {
			// fees = change, remove change output
			ptx.Outputs = ptx.Outputs[:len(ptx.Outputs)-1]
		} else if feeAmount < change {
			// change covers the fees, reduce change amount
			ptx.Outputs[len(ptx.Outputs)-1].Value = change - feeAmount
		} else {
			// change is not enough to cover fees, re-select utxos
			if change > 0 {
				// remove change output if present
				ptx.Outputs = ptx.Outputs[:len(ptx.Outputs)-1]
			}
			newUtxos, change, err := b.wallet.SelectUtxos(ctx, b.net.AssetID, feeAmount-change)
			if err != nil {
				return nil, err
			}

			if change > 0 {
				if err := updater.AddOutputs([]psetv2.OutputArgs{
					{
						Asset:  b.net.AssetID,
						Amount: change,
						Script: aspScript,
					},
				}); err != nil {
					return nil, err
				}
			}

			if err := addInputs(updater, newUtxos); err != nil {
				return nil, err
			}
		}
	} else if feeAmount-dust > 0 {
		newUtxos, change, err := b.wallet.SelectUtxos(ctx, b.net.AssetID, feeAmount-dust)
		if err != nil {
			return nil, err
		}

		if change > 0 {
			if change < dustLimit {
				feeAmount += change
			} else {
				if err := updater.AddOutputs([]psetv2.OutputArgs{
					{
						Asset:  b.net.AssetID,
						Amount: change,
						Script: aspScript,
					},
				}); err != nil {
					return nil, err
				}
			}
		}

		if err := addInputs(updater, newUtxos); err != nil {
			return nil, err
		}
	}

	// add fee output
	if err := updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  b.net.AssetID,
			Amount: feeAmount,
		},
	}); err != nil {
		return nil, err
	}

	return ptx, nil
}

func (b *txBuilder) createConnectors(
	poolTx string, payments []domain.Payment, connectorAddress string, minRelayFee uint64,
) ([]*psetv2.Pset, error) {
	txid, _ := getTxid(poolTx)

	aspScript, err := address.ToOutputScript(connectorAddress)
	if err != nil {
		return nil, err
	}

	connectorOutput := psetv2.OutputArgs{
		Asset:  b.net.AssetID,
		Script: aspScript,
		Amount: connectorAmount,
	}

	numberOfConnectors := countSpentVtxos(payments)

	previousInput := psetv2.InputArgs{
		Txid:    txid,
		TxIndex: 1,
	}

	if numberOfConnectors == 1 {
		outputs := []psetv2.OutputArgs{connectorOutput}
		connectorTx, err := craftConnectorTx(previousInput, aspScript, outputs, minRelayFee)
		if err != nil {
			return nil, err
		}

		return []*psetv2.Pset{connectorTx}, nil
	}

	totalConnectorAmount := (connectorAmount+minRelayFee)*numberOfConnectors - minRelayFee

	connectors := make([]*psetv2.Pset, 0, numberOfConnectors-1)
	for i := uint64(0); i < numberOfConnectors-1; i++ {
		outputs := []psetv2.OutputArgs{connectorOutput}
		totalConnectorAmount -= connectorAmount
		totalConnectorAmount -= minRelayFee
		if totalConnectorAmount > 0 {
			outputs = append(outputs, psetv2.OutputArgs{
				Asset:  b.net.AssetID,
				Script: aspScript,
				Amount: totalConnectorAmount,
			})
		}
		connectorTx, err := craftConnectorTx(previousInput, aspScript, outputs, minRelayFee)
		if err != nil {
			return nil, err
		}

		txid, _ := getPsetId(connectorTx)

		previousInput = psetv2.InputArgs{
			Txid:    txid,
			TxIndex: 1,
		}

		connectors = append(connectors, connectorTx)
	}

	return connectors, nil
}

func (b *txBuilder) createForfeitTxs(
	aspPubkey *secp256k1.PublicKey, payments []domain.Payment, connectors []*psetv2.Pset,
) ([]string, error) {
	aspScript, err := p2wpkhScript(aspPubkey, b.net)
	if err != nil {
		return nil, err
	}

	forfeitTxs := make([]string, 0)
	for _, payment := range payments {
		for _, vtxo := range payment.Inputs {
			pubkeyBytes, err := hex.DecodeString(vtxo.Pubkey)
			if err != nil {
				return nil, fmt.Errorf("failed to decode pubkey: %s", err)
			}

			vtxoPubkey, err := secp256k1.ParsePubKey(pubkeyBytes)
			if err != nil {
				return nil, err
			}

			vtxoScript, vtxoTaprootTree, err := b.getLeafScriptAndTree(vtxoPubkey, aspPubkey)
			if err != nil {
				return nil, err
			}

			var forfeitProof *taproot.TapscriptElementsProof

			for _, proof := range vtxoTaprootTree.LeafMerkleProofs {
				isForfeit, err := (&tree.ForfeitClosure{}).Decode(proof.Script)
				if !isForfeit || err != nil {
					continue
				}

				forfeitProof = &proof
				break
			}

			if forfeitProof == nil {
				return nil, fmt.Errorf("forfeit proof not found")
			}

			for _, connector := range connectors {
				txs, err := craftForfeitTxs(
					connector, vtxo, *forfeitProof, vtxoScript, aspScript,
				)
				if err != nil {
					return nil, err
				}

				forfeitTxs = append(forfeitTxs, txs...)
			}
		}
	}
	return forfeitTxs, nil
}
