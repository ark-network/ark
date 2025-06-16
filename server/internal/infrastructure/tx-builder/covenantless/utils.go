package txbuilder

import (
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common"
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
	cosignersPublicKeys [][]string,
) ([]tree.Leaf, error) {
	if len(cosignersPublicKeys) != len(requests) {
		return nil, fmt.Errorf("cosigners public keys length %d does not match requests length %d", len(cosignersPublicKeys), len(requests))
	}

	leaves := make([]tree.Leaf, 0)
	for i, request := range requests {
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

				leaves = append(leaves, tree.Leaf{
					Script:              hex.EncodeToString(script),
					Amount:              receiver.Amount,
					CosignersPublicKeys: cosignersPublicKeys[i],
				})
			}
		}
	}
	return leaves, nil
}

func taprootOutputScript(taprootKey *secp256k1.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().AddOp(txscript.OP_1).AddData(schnorr.SerializePubKey(taprootKey)).Script()
}
