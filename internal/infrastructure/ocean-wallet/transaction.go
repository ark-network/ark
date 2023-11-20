package oceanwallet

import (
	"context"
	"fmt"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/vulpemventures/go-elements/psetv2"
	"google.golang.org/grpc"
)

const msatsPerByte = 110

type tx struct {
	client pb.TransactionServiceClient
}

func newTx(conn *grpc.ClientConn) *tx {
	return &tx{pb.NewTransactionServiceClient(conn)}
}

func (m *tx) GetTransaction(
	ctx context.Context, txid string,
) (string, error) {
	res, err := m.client.GetTransaction(ctx, &pb.GetTransactionRequest{
		Txid: txid,
	})
	if err != nil {
		return "", err
	}
	return res.GetTxHex(), nil
}

func (m *tx) UpdatePset(
	ctx context.Context, pset string,
	ins []ports.TxInput, outs []ports.TxOutput,
) (string, error) {
	res, err := m.client.UpdatePset(ctx, &pb.UpdatePsetRequest{
		Pset:    pset,
		Inputs:  inputList(ins).toProto(),
		Outputs: outputList(outs).toProto(),
	})
	if err != nil {
		return "", err
	}
	return res.GetPset(), nil
}

func (m *tx) SignPset(
	ctx context.Context, pset string, extractRawTx bool,
) (string, error) {
	res, err := m.client.SignPset(ctx, &pb.SignPsetRequest{
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

func (m *tx) Transfer(
	ctx context.Context, outs []ports.TxOutput,
) (string, error) {
	res, err := m.client.Transfer(ctx, &pb.TransferRequest{
		AccountName:      accountLabel,
		Receivers:        outputList(outs).toProto(),
		MillisatsPerByte: msatsPerByte,
	})
	if err != nil {
		return "", err
	}
	return res.GetTxHex(), nil
}

func (m *tx) BroadcastTransaction(
	ctx context.Context, txHex string,
) (string, error) {
	res, err := m.client.BroadcastTransaction(
		ctx, &pb.BroadcastTransactionRequest{
			TxHex: txHex,
		},
	)
	if err != nil {
		return "", err
	}
	return res.GetTxid(), nil
}

type inputList []ports.TxInput

func (l inputList) toProto() []*pb.Input {
	list := make([]*pb.Input, 0, len(l))
	for _, in := range l {
		list = append(list, &pb.Input{
			Txid:          in.GetTxid(),
			Index:         in.GetIndex(),
			Script:        in.GetScript(),
			ScriptsigSize: uint64(in.GetScriptSigSize()),
			WitnessSize:   uint64(in.GetWitnessSize()),
		})
	}
	return list
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
