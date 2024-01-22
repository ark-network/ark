package oceanwallet

import (
	"context"
	"fmt"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

func (s *service) SignPset(
	ctx context.Context, pset string, extractRawTx bool,
) (string, error) {
	ptx, err := psetv2.NewPsetFromBase64(pset)
	if err != nil {
		return "", err
	}

	updater, err := psetv2.NewUpdater(ptx)
	if err != nil {
		return "", err
	}

	for inputIndex, in := range ptx.Inputs {
		if in.WitnessUtxo == nil {
			resp, err := s.txClient.GetTransaction(ctx, &pb.GetTransactionRequest{
				Txid: chainhash.Hash(in.PreviousTxid).String(),
			})
			if err != nil {
				return "", err
			}

			txHex := resp.GetTxHex()
			tx, err := transaction.NewTxFromHex(txHex)
			if err != nil {
				return "", err
			}

			if len(tx.Outputs) <= int(in.PreviousTxIndex) {
				return "", fmt.Errorf("invalid previous tx index, cannot set witness utxo")
			}

			if err := updater.AddInWitnessUtxo(inputIndex, tx.Outputs[in.PreviousTxIndex]); err != nil {
				return "", err
			}
		}
	}

	updatedPset, err := updater.Pset.ToBase64()
	if err != nil {
		return "", err
	}

	res, err := s.txClient.SignPset(ctx, &pb.SignPsetRequest{
		Pset: updatedPset,
	})
	if err != nil {
		return "", err
	}
	signedPset := res.GetPset()

	if !extractRawTx {
		return signedPset, nil
	}

	ptx, err = psetv2.NewPsetFromBase64(signedPset)
	if err != nil {
		return "", err
	}

	if err := psetv2.MaybeFinalizeAll(ptx); err != nil {
		return "", fmt.Errorf("failed to finalize signed pset: %s", err)
	}

	extractedTx, err := psetv2.Extract(ptx)
	if err != nil {
		return "", fmt.Errorf("failed to extract signed pset: %s", err)
	}

	txHex, err := extractedTx.ToHex()
	if err != nil {
		return "", fmt.Errorf("failed to convert extracted tx to hex: %s", err)
	}

	return txHex, nil
}

func (s *service) SelectUtxos(ctx context.Context, asset string, amount uint64) ([]ports.TxInput, uint64, error) {
	res, err := s.txClient.SelectUtxos(ctx, &pb.SelectUtxosRequest{
		AccountName:  accountLabel,
		TargetAsset:  asset,
		TargetAmount: amount,
	})
	if err != nil {
		return nil, 0, err
	}

	inputs := make([]ports.TxInput, 0, len(res.GetUtxos()))
	for _, utxo := range res.GetUtxos() {
		inputs = append(inputs, utxo)
	}

	return inputs, res.GetChange(), nil
}

func (s *service) BroadcastTransaction(
	ctx context.Context, txHex string,
) (string, error) {
	res, err := s.txClient.BroadcastTransaction(
		ctx, &pb.BroadcastTransactionRequest{
			TxHex: txHex,
		},
	)
	if err != nil {
		return "", err
	}
	return res.GetTxid(), nil
}
