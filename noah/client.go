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

func getVtxos(ctx *cli.Context, client arkv1.ArkServiceClient) ([]vtxo, error) {
	addr, err := getAddress()
	if err != nil {
		return nil, err
	}

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

// get the ark client and a function closing the connection
func getArkClient(ctx *cli.Context) (arkv1.ArkServiceClient, func(), error) {
	conn, err := getConn(ctx)
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

// connect to the ark rpc URL specified in the config
func getConn(ctx *cli.Context) (*grpc.ClientConn, error) {
	state, err := getState()
	if err != nil {
		return nil, err
	}

	rpcUrl, ok := state["ark_url"]
	if !ok {
		return nil, fmt.Errorf("missing ark_url")
	}

	conn, err := grpc.Dial(rpcUrl, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return conn, nil
}
