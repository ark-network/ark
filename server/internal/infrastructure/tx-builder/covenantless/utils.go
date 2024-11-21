package txbuilder

import (
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func getOnchainOutputs(
	payments []domain.Payment, network *chaincfg.Params,
) ([]*wire.TxOut, error) {
	outputs := make([]*wire.TxOut, 0)
	for _, payment := range payments {
		for _, receiver := range payment.Receivers {
			if receiver.IsOnchain() {
				receiverAddr, err := btcutil.DecodeAddress(receiver.OnchainAddress, network)
				if err != nil {
					return nil, err
				}

				receiverScript, err := txscript.PayToAddrScript(receiverAddr)
				if err != nil {
					return nil, err
				}

				outputs = append(outputs, &wire.TxOut{
					Value:    int64(receiver.Amount),
					PkScript: receiverScript,
				})
			}
		}
	}
	return outputs, nil
}

func getOutputVtxosLeaves(
	payments []domain.Payment,
) ([]tree.VtxoLeaf, error) {
	leaves := make([]tree.VtxoLeaf, 0)
	for _, payment := range payments {
		for _, receiver := range payment.Receivers {
			if !receiver.IsOnchain() {
				leaves = append(leaves, tree.VtxoLeaf{
					PubKey: receiver.PubKey,
					Amount: receiver.Amount,
				})
			}
		}
	}
	return leaves, nil
}

func countSpentVtxos(payments []domain.Payment) uint64 {
	var sum uint64
	for _, payment := range payments {
		sum += uint64(len(payment.Inputs))
	}
	return sum
}

func taprootOutputScript(taprootKey *secp256k1.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().AddOp(txscript.OP_1).AddData(schnorr.SerializePubKey(taprootKey)).Script()
}

func isOnchainOnly(payments []domain.Payment) bool {
	for _, p := range payments {
		for _, r := range p.Receivers {
			if !r.IsOnchain() {
				return false
			}
		}
	}
	return true
}
