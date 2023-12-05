package oceanwallet

import (
	"context"
	"fmt"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/vulpemventures/go-elements/psetv2"
)

const msatsPerByte = 110

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

	ptx, _ := psetv2.NewPsetFromBase64(signedPset)
	if err := psetv2.MaybeFinalizeAll(ptx); err != nil {
		return "", fmt.Errorf("failed to finalize signed pset: %s", err)
	}
	return ptx.ToBase64()
}

func (s *service) Transfer(
	ctx context.Context, outs []ports.TxOutput,
) (string, error) {
	res, err := s.txClient.Transfer(ctx, &pb.TransferRequest{
		AccountName:      accountLabel,
		Receivers:        outputList(outs).toProto(),
		MillisatsPerByte: msatsPerByte,
	})
	if err != nil {
		return "", err
	}
	return res.GetTxHex(), nil
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

type outputList []ports.TxOutput

func (l outputList) toProto() []*pb.Output {
	list := make([]*pb.Output, 0, len(l))
	for _, out := range l {
		list = append(list, &pb.Output{
			Amount: out.GetAmount(),
			Script: out.GetScript(),
		})
	}
	return list
}
