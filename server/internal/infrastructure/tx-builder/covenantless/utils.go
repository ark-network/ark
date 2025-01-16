package txbuilder

import (
	"fmt"

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
	requests []domain.TxRequest, network *chaincfg.Params,
) ([]*wire.TxOut, error) {
	outputs := make([]*wire.TxOut, 0)
	for _, request := range requests {
		for _, receiver := range request.Receivers {
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
	requests []domain.TxRequest,
	musig2Data []*tree.Musig2,
) ([]tree.VtxoLeaf, error) {
	if len(musig2Data) != len(requests) {
		return nil, fmt.Errorf("musig2 data length %d does not match requests length %d", len(musig2Data), len(requests))
	}

	leaves := make([]tree.VtxoLeaf, 0)
	for i, request := range requests {
		for _, receiver := range request.Receivers {
			if !receiver.IsOnchain() {
				leaves = append(leaves, tree.VtxoLeaf{
					PubKey:     receiver.PubKey,
					Amount:     receiver.Amount,
					Musig2Data: musig2Data[i],
				})
			}
		}
	}
	return leaves, nil
}

func countSpentVtxos(requests []domain.TxRequest) uint64 {
	var sum uint64
	for _, request := range requests {
		sum += uint64(len(request.Inputs))
	}
	return sum
}

func taprootOutputScript(taprootKey *secp256k1.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().AddOp(txscript.OP_1).AddData(schnorr.SerializePubKey(taprootKey)).Script()
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
