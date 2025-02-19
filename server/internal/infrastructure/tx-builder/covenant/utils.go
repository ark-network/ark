package txbuilder

import (
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

func p2wpkhScript(pubkey *secp256k1.PublicKey, net *network.Network) ([]byte, error) {
	payment := payment.FromPublicKey(pubkey, net, nil)
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

	return getPsetId(pset)
}

func getPsetId(pset *psetv2.Pset) (string, error) {
	utx, err := pset.UnsignedTx()
	if err != nil {
		return "", err
	}

	return utx.TxHash().String(), nil
}

func getOnchainOutputs(
	requests []domain.TxRequest, net *network.Network,
) ([]psetv2.OutputArgs, error) {
	outputs := make([]psetv2.OutputArgs, 0)
	for _, request := range requests {
		for _, receiver := range request.Receivers {
			if receiver.IsOnchain() {
				receiverScript, err := address.ToOutputScript(receiver.OnchainAddress)
				if err != nil {
					return nil, err
				}

				outputs = append(outputs, psetv2.OutputArgs{
					Script: receiverScript,
					Amount: receiver.Amount,
					Asset:  net.AssetID,
				})
			}
		}
	}
	return outputs, nil
}

func getOutputVtxosLeaves(
	requests []domain.TxRequest,
) ([]tree.Leaf, error) {
	receivers := make([]tree.Leaf, 0)
	for _, request := range requests {
		for _, receiver := range request.Receivers {
			if !receiver.IsOnchain() {
				pubkeyBytes, err := hex.DecodeString(receiver.PubKey)
				if err != nil {
					return nil, fmt.Errorf("failed to decode pubkey: %s", err)
				}

				pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
				if err != nil {
					return nil, fmt.Errorf("failed to parse pubkey: %s", err)
				}

				script, err := common.P2TRScript(pubkey)
				if err != nil {
					return nil, fmt.Errorf("failed to create script: %s", err)
				}

				receivers = append(receivers, tree.Leaf{
					Script: hex.EncodeToString(script),
					Amount: receiver.Amount,
				})
			}
		}
	}
	return receivers, nil
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

	return transaction.NewTxOutput(assetBytes, valueBytes, scriptBytes), nil
}

func countSpentVtxos(requests []domain.TxRequest) uint64 {
	var sum uint64
	for _, request := range requests {
		sum += uint64(len(request.Inputs))
	}
	return sum
}

func addInputs(
	updater *psetv2.Updater,
	inputs []ports.TxInput,
) error {
	for _, in := range inputs {
		inputArg := psetv2.InputArgs{
			Txid:    in.GetTxid(),
			TxIndex: in.GetIndex(),
		}

		witnessUtxo, err := toWitnessUtxo(in)
		if err != nil {
			return err
		}

		if err := updater.AddInputs([]psetv2.InputArgs{inputArg}); err != nil {
			return err
		}

		index := int(updater.Pset.Global.InputCount) - 1
		if err := updater.AddInWitnessUtxo(index, witnessUtxo); err != nil {
			return err
		}

		if err := updater.AddInSighashType(index, txscript.SigHashAll); err != nil {
			return err
		}
	}

	return nil
}

func isOnchainOnly(requests []domain.TxRequest) bool {
	for _, request := range requests {
		for _, r := range request.Receivers {
			if !r.IsOnchain() {
				return false
			}
		}
	}
	return true
}
