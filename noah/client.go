package main

import (
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type vtxo struct {
	amount uint64
	txid   string
	vout   uint32
}

func getVtxos(
	ctx *cli.Context, client arkv1.ArkServiceClient, addr string,
) ([]vtxo, error) {
	response, err := client.ListVtxos(ctx.Context, &arkv1.ListVtxosRequest{
		Address: addr,
	})
	if err != nil {
		return nil, err
	}

	vtxos := make([]vtxo, 0, len(response.Vtxos))
	for _, v := range response.Vtxos {
		vtxos = append(vtxos, vtxo{
			amount: v.Receiver.Amount,
			txid:   v.Outpoint.Txid,
			vout:   v.Outpoint.Vout,
		})
	}

	return vtxos, nil
}

func getClientFromState(ctx *cli.Context) (arkv1.ArkServiceClient, func(), error) {
	state, err := getState()
	if err != nil {
		return nil, nil, err
	}
	addr, ok := state["ark_url"]
	if !ok {
		return nil, nil, fmt.Errorf("missing ark_url")
	}
	return getClient(ctx, addr)
}

func getClient(ctx *cli.Context, addr string) (arkv1.ArkServiceClient, func(), error) {
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}

	client := arkv1.NewArkServiceClient(conn)

	closeFn := func() {
		err := conn.Close()
		if err != nil {
			fmt.Printf("error closing connection: %s\n", err)
		}
	}

	return client, closeFn, nil
}
