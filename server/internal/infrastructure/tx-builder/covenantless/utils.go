package txbuilder

import (
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func p2trScript(publicKey *secp256k1.PublicKey, net *chaincfg.Params) ([]byte, error) {
	tapKey := txscript.ComputeTaprootKeyNoScript(publicKey)

	payment, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(tapKey),
		net,
	)
	if err != nil {
		return nil, err
	}

	return payment.ScriptAddress(), nil
}

func getOnchainReceivers(
	payments []domain.Payment,
) []domain.Receiver {
	receivers := make([]domain.Receiver, 0)
	for _, payment := range payments {
		for _, receiver := range payment.Receivers {
			if receiver.IsOnchain() {
				receivers = append(receivers, receiver)
			}
		}
	}
	return receivers
}

func getOffchainReceivers(
	payments []domain.Payment,
) []bitcointree.Receiver {
	receivers := make([]bitcointree.Receiver, 0)
	for _, payment := range payments {
		for _, receiver := range payment.Receivers {
			if !receiver.IsOnchain() {
				receivers = append(receivers, bitcointree.Receiver{
					Pubkey: receiver.Pubkey,
					Amount: receiver.Amount,
				})
			}
		}
	}
	return receivers
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
