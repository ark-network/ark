package main

import (
	"fmt"
	"time"

	arkgrpcclient "github.com/ark-network/ark-sdk/grpc"
	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/urfave/cli/v2"
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
	client, cleanFn, err := arkgrpcclient.New(addr)
	return client.Service(), cleanFn, err
}
