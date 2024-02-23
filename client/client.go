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

type JSONVtxo struct {
	Amount   uint64
	Txid     string
	Vout     uint32
	PoolTxid string
	ExpireAt int64
}

func (v *vtxo) toJSON() JSONVtxo {
	expireAt := int64(0)
	if v.expireAt != nil {
		expireAt = v.expireAt.Unix()
	}
	return JSONVtxo{
		Amount:   v.amount,
		Txid:     v.txid,
		Vout:     v.vout,
		PoolTxid: v.poolTxid,
		ExpireAt: expireAt,
	}
}

func (v *JSONVtxo) toVtxo() vtxo {
	expireAt := time.Unix(v.ExpireAt, 0)
	return vtxo{
		amount:   v.Amount,
		txid:     v.Txid,
		vout:     v.Vout,
		poolTxid: v.PoolTxid,
		expireAt: &expireAt,
	}
}

func getVtxos(
	ctx *cli.Context,
	explorer Explorer,
	client arkv1.ArkServiceClient,
	addr string,
	withExpiration bool,
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
			amount:   v.Receiver.Amount,
			txid:     v.Outpoint.Txid,
			vout:     v.Outpoint.Vout,
			poolTxid: v.PoolTxid,
		})
	}

	if !withExpiration {
		return vtxos, nil
	}

	redeemBranches, err := getRedeemBranches(ctx, explorer, client, vtxos)
	if err != nil {
		return nil, err
	}

	for vtxoTxid, branch := range redeemBranches {
		expiration, err := branch.ExpireAt()
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
	state, err := getState()
	if err != nil {
		return nil, nil, err
	}
	addr, ok := state["ark_url"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("missing ark_url")
	}
	return getClient(ctx, addr)
}

func getClient(ctx *cli.Context, addr string) (arkv1.ArkServiceClient, func(), error) {
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
