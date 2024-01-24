package txbuilder

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
	"github.com/vulpemventures/go-elements/transaction"
)

const (
	connectorAmount = 450
	poolTxFeeAmount = 300
)

var emptyNonce = []byte{0x00}

type txBuilder struct {
	net *network.Network
}

func NewTxBuilder(net network.Network) ports.TxBuilder {
	return &txBuilder{
		net: &net,
	}
}

func p2wpkhScript(publicKey *secp256k1.PublicKey, net *network.Network) ([]byte, error) {
	payment := payment.FromPublicKey(publicKey, net, nil)
	addr, err := payment.WitnessPubKeyHash()
	if err != nil {
		return nil, err
	}

	return address.ToOutputScript(addr)
}

func getTxid(txStr string) (string, error) {
	pset, err := psetv2.NewPsetFromBase64(txStr)
	if err != nil {
		return "", err
	}

	utx, err := pset.UnsignedTx()
	if err != nil {
		return "", err
	}

	return utx.TxHash().String(), nil
}

func (b *txBuilder) GetLeafOutputScript(userPubkey, aspPubkey *secp256k1.PublicKey) ([]byte, error) {
	outputScript, _, err := b.getLeafTaprootTree(userPubkey, aspPubkey)
	if err != nil {
		return nil, err
	}
	return outputScript, nil
}

// BuildForfeitTxs implements ports.TxBuilder.
func (b *txBuilder) BuildForfeitTxs(
	aspPubkey *secp256k1.PublicKey, poolTx string, payments []domain.Payment,
) (connectors []string, forfeitTxs []string, err error) {
	poolTxID, err := getTxid(poolTx)
	if err != nil {
		return nil, nil, err
	}

	aspScript, err := p2wpkhScript(aspPubkey, b.net)
	if err != nil {
		return nil, nil, err
	}

	numberOfConnectors := numberOfVTXOs(payments)

	connectors, err = createConnectors(
		poolTxID,
		1,
		psetv2.OutputArgs{
			Asset:  b.net.AssetID,
			Amount: connectorAmount,
			Script: aspScript,
		},
		aspScript,
		numberOfConnectors,
	)
	if err != nil {
		return nil, nil, err
	}

	connectorsAsInputs, err := connectorsToInputArgs(connectors)
	if err != nil {
		return nil, nil, err
	}

	lbtc, _ := elementsutil.AssetHashToBytes(b.net.AssetID)

	forfeitTxs = make([]string, 0)

	for _, payment := range payments {
		for _, vtxo := range payment.Inputs {
			vtxoAmount, err := elementsutil.ValueToBytes(vtxo.Amount)
			if err != nil {
				return nil, nil, err
			}

			pubkeyBytes, err := hex.DecodeString(vtxo.Pubkey)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to decode pubkey: %s", err)
			}

			vtxoPubkey, err := secp256k1.ParsePubKey(pubkeyBytes)
			if err != nil {
				return nil, nil, err
			}

			vtxoOutputScript, vtxoTaprootTree, err := b.getLeafTaprootTree(vtxoPubkey, aspPubkey)
			if err != nil {
				return nil, nil, err
			}

			for _, connector := range connectorsAsInputs {
				forfeitTx, err := createForfeitTx(
					connector.input,
					connector.witnessUtxo,
					psetv2.InputArgs{
						Txid:    vtxo.Txid,
						TxIndex: vtxo.VOut,
					},
					&transaction.TxOutput{
						Asset:  lbtc,
						Value:  vtxoAmount,
						Script: vtxoOutputScript,
					},
					vtxoTaprootTree,
					aspScript,
					*b.net,
				)
				if err != nil {
					return nil, nil, err
				}

				forfeitTxs = append(forfeitTxs, forfeitTx)
			}
		}

	}

	return connectors, forfeitTxs, nil
}

// BuildPoolTx implements ports.TxBuilder.
func (b *txBuilder) BuildPoolTx(
	aspPubkey *secp256k1.PublicKey,
	wallet ports.WalletService,
	payments []domain.Payment,
	minRelayFee uint64,
) (poolTx string, congestionTree tree.CongestionTree, err error) {
	aspScriptBytes, err := p2wpkhScript(aspPubkey, b.net)
	if err != nil {
		return
	}

	offchainReceivers, onchainReceivers := receiversFromPayments(payments)
	numberOfConnectors := numberOfVTXOs(payments)
	connectorOutputAmount := connectorAmount * numberOfConnectors

	ctx := context.Background()

	makeTree, sharedOutputScript, sharedOutputAmount, err := buildCongestionTree(
		b.net,
		aspPubkey,
		offchainReceivers,
		minRelayFee,
	)
	if err != nil {
		return
	}

	outputs := []psetv2.OutputArgs{
		{
			Asset:  b.net.AssetID,
			Amount: sharedOutputAmount,
			Script: sharedOutputScript,
		},
		{
			Asset:  b.net.AssetID,
			Amount: connectorOutputAmount,
			Script: aspScriptBytes,
		},
		{
			Asset:  b.net.AssetID,
			Amount: poolTxFeeAmount,
		},
	}

	targetAmount := sharedOutputAmount + connectorOutputAmount + poolTxFeeAmount

	for _, receiver := range onchainReceivers {
		targetAmount += receiver.Amount

		receiverScript, err := address.ToOutputScript(receiver.OnchainAddress)
		if err != nil {
			return "", nil, err
		}

		outputs = append(outputs, psetv2.OutputArgs{
			Asset:  b.net.AssetID,
			Amount: receiver.Amount,
			Script: receiverScript,
		})
	}

	utxos, change, err := wallet.SelectUtxos(ctx, b.net.AssetID, targetAmount)
	if err != nil {
		return
	}

	if change > 0 {
		outputs = append(outputs, psetv2.OutputArgs{
			Asset:  b.net.AssetID,
			Amount: change,
			Script: aspScriptBytes,
		})
	}

	ptx, err := psetv2.New(toInputArgs(utxos), outputs, nil)
	if err != nil {
		return
	}

	updater, err := psetv2.NewUpdater(ptx)
	if err != nil {
		return
	}

	for i, utxo := range utxos {
		witnessUtxo, err := toWitnessUtxo(utxo)
		if err != nil {
			return "", nil, err
		}

		if err := updater.AddInWitnessUtxo(i, witnessUtxo); err != nil {
			return "", nil, err
		}

		if err := updater.AddInSighashType(i, txscript.SigHashAll); err != nil {
			return "", nil, err
		}
	}

	utx, err := ptx.UnsignedTx()
	if err != nil {
		return
	}

	tree, err := makeTree(psetv2.InputArgs{
		Txid:    utx.TxHash().String(),
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

func (b *txBuilder) getLeafTaprootTree(userPubkey, aspPubkey *secp256k1.PublicKey) ([]byte, *taproot.IndexedElementsTapScriptTree, error) {
	sweepTaprootLeaf, err := tree.SweepScript(aspPubkey, expirationTime)
	if err != nil {
		return nil, nil, err
	}

	vtxoLeaf, err := tree.VtxoScript(userPubkey)
	if err != nil {
		return nil, nil, err
	}

	leafTaprootTree := taproot.AssembleTaprootScriptTree(*vtxoLeaf, *sweepTaprootLeaf)
	root := leafTaprootTree.RootNode.TapHash()

	unspendableKeyBytes, _ := hex.DecodeString(tree.UnspendablePoint)
	unspendableKey, _ := secp256k1.ParsePubKey(unspendableKeyBytes)

	taprootKey := taproot.ComputeTaprootOutputKey(
		unspendableKey,
		root[:],
	)

	outputScript, err := taprootOutputScript(taprootKey)
	if err != nil {
		return nil, nil, err
	}

	return outputScript, leafTaprootTree, nil
}

type inputWithWitnessUtxo struct {
	input       psetv2.InputArgs
	witnessUtxo *transaction.TxOutput
}

func connectorsToInputArgs(connectors []string) ([]inputWithWitnessUtxo, error) {
	inputs := make([]inputWithWitnessUtxo, 0, len(connectors)+1)
	for i, psetb64 := range connectors {
		pset, err := psetv2.NewPsetFromBase64(psetb64)
		if err != nil {
			return nil, err
		}

		utx, err := pset.UnsignedTx()
		if err != nil {
			return nil, err
		}

		txID := utx.TxHash().String()

		input := psetv2.InputArgs{
			Txid:    txID,
			TxIndex: 0,
		}
		inputs = append(inputs, inputWithWitnessUtxo{
			input:       input,
			witnessUtxo: utx.Outputs[0],
		})

		if i == len(connectors)-1 && len(utx.Outputs) > 1 {
			input := psetv2.InputArgs{
				Txid:    txID,
				TxIndex: 1,
			}
			inputs = append(inputs, inputWithWitnessUtxo{
				input:       input,
				witnessUtxo: utx.Outputs[1],
			})
		}
	}
	return inputs, nil
}

func numberOfVTXOs(payments []domain.Payment) uint64 {
	var sum uint64
	for _, payment := range payments {
		sum += uint64(len(payment.Inputs))
	}
	return sum
}

func receiversFromPayments(
	payments []domain.Payment,
) (offchainReceivers, onchainReceivers []domain.Receiver) {
	for _, payment := range payments {
		for _, receiver := range payment.Receivers {
			if receiver.IsOnchain() {
				onchainReceivers = append(onchainReceivers, receiver)
			} else {
				offchainReceivers = append(offchainReceivers, receiver)
			}
		}
	}
	return
}

func toInputArgs(
	ins []ports.TxInput,
) []psetv2.InputArgs {
	inputs := make([]psetv2.InputArgs, 0, len(ins))
	for _, in := range ins {
		inputs = append(inputs, psetv2.InputArgs{
			Txid:    in.GetTxid(),
			TxIndex: in.GetIndex(),
		})
	}
	return inputs
}

func toWitnessUtxo(in ports.TxInput) (*transaction.TxOutput, error) {
	valueBytes, err := elementsutil.ValueToBytes(in.GetValue())
	if err != nil {
		return nil, fmt.Errorf("failed to convert value to bytes: %s", err)
	}

	assetBytes, err := elementsutil.AssetHashToBytes(in.GetAsset())
	if err != nil {
		return nil, fmt.Errorf("failed to convert asset to bytes: %s", err)
	}

	scriptBytes, err := hex.DecodeString(in.GetScript())
	if err != nil {
		return nil, fmt.Errorf("failed to decode script: %s", err)
	}

	return &transaction.TxOutput{
		Asset:           assetBytes,
		Value:           valueBytes,
		Script:          scriptBytes,
		Nonce:           emptyNonce,
		RangeProof:      nil,
		SurjectionProof: nil,
	}, err
}
