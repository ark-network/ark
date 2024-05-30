package main

import (
	"fmt"
	"strings"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type vtxo struct {
	amount   uint64
	txid     string
	vout     uint32
	poolTxid string
	expireAt *time.Time
}

func getVtxos(
	ctx *cli.Context, explorer Explorer, client arkv1.ArkServiceClient,
	addr string, computeExpiration bool,
) ([]vtxo, error) {
	response, err := client.ListVtxos(ctx.Context, &arkv1.ListVtxosRequest{
		Address: addr,
	})
	if err != nil {
		return nil, err
	}

	vtxos := make([]vtxo, 0, len(response.GetSpendableVtxos()))
	for _, v := range response.GetSpendableVtxos() {
		var expireAt *time.Time
		if v.ExpireAt > 0 {
			t := time.Unix(v.ExpireAt, 0)
			expireAt = &t
		}
		if v.Swept {
			continue
		}
		vtxos = append(vtxos, vtxo{
			amount:   v.Receiver.Amount,
			txid:     v.Outpoint.Txid,
			vout:     v.Outpoint.Vout,
			poolTxid: v.PoolTxid,
			expireAt: expireAt,
		})
	}

	if !computeExpiration {
		return vtxos, nil
	}

	redeemBranches, err := getRedeemBranches(ctx.Context, explorer, client, vtxos)
	if err != nil {
		return nil, err
	}

	for vtxoTxid, branch := range redeemBranches {
		expiration, err := branch.expireAt(ctx)
		if err != nil {
			return nil, err
		}

		for i, vtxo := range vtxos {
			if vtxo.txid == vtxoTxid {
				vtxos[i].expireAt = expiration
				break
			}
		}
	}

	return vtxos, nil
}

func getClientFromState(ctx *cli.Context) (arkv1.ArkServiceClient, func(), error) {
	state, err := getState(ctx)
	if err != nil {
		return nil, nil, err
	}
	addr := state[ASP_URL]
	if len(addr) <= 0 {
		return nil, nil, fmt.Errorf("missing asp url")
	}
	return getClient(addr)
}

func getClient(addr string) (arkv1.ArkServiceClient, func(), error) {
	creds := insecure.NewCredentials()
	port := 80
	if strings.HasPrefix(addr, "https://") {
		addr = strings.TrimPrefix(addr, "https://")
		creds = credentials.NewTLS(nil)
		port = 443
	}
	if !strings.Contains(addr, ":") {
		addr = fmt.Sprintf("%s:%d", addr, port)
	}
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds))
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
