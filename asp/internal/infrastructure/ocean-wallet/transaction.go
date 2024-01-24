package oceanwallet

import (
	"context"
	"fmt"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/vulpemventures/go-elements/psetv2"
)

const (
	zero32 = "0000000000000000000000000000000000000000000000000000000000000000"
)

func (s *service) SignPset(
	ctx context.Context, pset string, extractRawTx bool,
) (string, error) {
	res, err := s.txClient.SignPset(ctx, &pb.SignPsetRequest{
		Pset: pset,
	})
	if err != nil {
		return "", err
	}
	signedPset := res.GetPset()

	if !extractRawTx {
		return signedPset, nil
	}

	ptx, err := psetv2.NewPsetFromBase64(signedPset)
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
		// check that the utxos are not confidential
		if utxo.GetAssetBlinder() != zero32 || utxo.GetValueBlinder() != zero32 {
			return nil, 0, fmt.Errorf("utxo is confidential")
		}

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
