package covenantless

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/client/utils"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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
	pending  bool
}

func getVtxos(
	ctx *cli.Context, explorer utils.Explorer, client arkv1.ArkServiceClient,
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
		if v.GetExpireAt() > 0 {
			t := time.Unix(v.ExpireAt, 0)
			expireAt = &t
		}
		if v.GetSwept() {
			continue
		}
		vtxos = append(vtxos, vtxo{
			amount:   v.GetReceiver().GetAmount(),
			txid:     v.GetOutpoint().GetTxid(),
			vout:     v.GetOutpoint().GetVout(),
			poolTxid: v.GetPoolTxid(),
			expireAt: expireAt,
			pending:  v.GetPending(),
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
	state, err := utils.GetState(ctx)
	if err != nil {
		return nil, nil, err
	}
	addr := state[utils.ASP_URL]
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
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
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

func getRedeemBranches(
	ctx context.Context, explorer utils.Explorer, client arkv1.ArkServiceClient,
	vtxos []vtxo,
) (map[string]*redeemBranch, error) {
	congestionTrees := make(map[string]tree.CongestionTree, 0)
	redeemBranches := make(map[string]*redeemBranch, 0)

	for _, vtxo := range vtxos {
		if _, ok := congestionTrees[vtxo.poolTxid]; !ok {
			round, err := client.GetRound(ctx, &arkv1.GetRoundRequest{
				Txid: vtxo.poolTxid,
			})
			if err != nil {
				return nil, err
			}

			treeFromRound := round.GetRound().GetCongestionTree()
			congestionTree, err := toCongestionTree(treeFromRound)
			if err != nil {
				return nil, err
			}

			congestionTrees[vtxo.poolTxid] = congestionTree
		}

		redeemBranch, err := newRedeemBranch(
			explorer, congestionTrees[vtxo.poolTxid], vtxo,
		)
		if err != nil {
			return nil, err
		}

		redeemBranches[vtxo.txid] = redeemBranch
	}

	return redeemBranches, nil
}

func toCongestionTree(treeFromProto *arkv1.Tree) (tree.CongestionTree, error) {
	levels := make(tree.CongestionTree, 0, len(treeFromProto.Levels))

	for _, level := range treeFromProto.Levels {
		nodes := make([]tree.Node, 0, len(level.Nodes))

		for _, node := range level.Nodes {
			nodes = append(nodes, tree.Node{
				Txid:       node.Txid,
				Tx:         node.Tx,
				ParentTxid: node.ParentTxid,
				Leaf:       false,
			})
		}

		levels = append(levels, nodes)
	}

	for j, treeLvl := range levels {
		for i, node := range treeLvl {
			if len(levels.Children(node.Txid)) == 0 {
				levels[j][i].Leaf = true
			}
		}
	}

	return levels, nil
}

// castCongestionTree converts a tree.CongestionTree to a repeated arkv1.TreeLevel
func castCongestionTree(congestionTree tree.CongestionTree) *arkv1.Tree {
	levels := make([]*arkv1.TreeLevel, 0, len(congestionTree))
	for _, level := range congestionTree {
		levelProto := &arkv1.TreeLevel{
			Nodes: make([]*arkv1.Node, 0, len(level)),
		}

		for _, node := range level {
			levelProto.Nodes = append(levelProto.Nodes, &arkv1.Node{
				Txid:       node.Txid,
				Tx:         node.Tx,
				ParentTxid: node.ParentTxid,
			})
		}

		levels = append(levels, levelProto)
	}
	return &arkv1.Tree{
		Levels: levels,
	}
}

func handleRoundStream(
	ctx *cli.Context, client arkv1.ArkServiceClient, paymentID string,
	vtxosToSign []vtxo, mustSignRoundTx bool,
	secKey *secp256k1.PrivateKey, receivers []*arkv1.Output,
) (poolTxID string, err error) {
	stream, err := client.GetEventStream(ctx.Context, &arkv1.GetEventStreamRequest{})
	if err != nil {
		return "", err
	}

	var pingStop func()
	pingReq := &arkv1.PingRequest{
		PaymentId: paymentID,
	}
	for pingStop == nil {
		pingStop = ping(ctx.Context, client, pingReq)
	}

	defer pingStop()

	for {
		event, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		if e := event.GetRoundFailed(); e != nil {
			pingStop()
			return "", fmt.Errorf("round failed: %s", e.GetReason())
		}

		if e := event.GetRoundFinalization(); e != nil {
			// stop pinging as soon as we receive some forfeit txs
			pingStop()

			roundTx := e.GetPoolTx()
			ptx, err := psbt.NewFromRawBytes(strings.NewReader(roundTx), true)
			if err != nil {
				return "", err
			}

			congestionTree, err := toCongestionTree(e.GetCongestionTree())
			if err != nil {
				return "", err
			}

			connectors := e.GetConnectors()

			aspPubkey, err := utils.GetAspPublicKey(ctx)
			if err != nil {
				return "", err
			}

			roundLifetime, err := utils.GetRoundLifetime(ctx)
			if err != nil {
				return "", err
			}

			minRelayFee, err := utils.GetMinRelayFee(ctx)
			if err != nil {
				return "", err
			}

			if !isOnchainOnly(receivers) {
				if err := bitcointree.ValidateCongestionTree(
					congestionTree, roundTx, aspPubkey, int64(roundLifetime), int64(minRelayFee),
				); err != nil {
					return "", err
				}
			}

			// TODO bitcoin validateConnectors
			// if err := common.ValidateConnectors(poolTx, connectors); err != nil {
			// 	return "", err
			// }

			unilateralExitDelay, err := utils.GetUnilateralExitDelay(ctx)
			if err != nil {
				return "", err
			}

			for _, receiver := range receivers {
				isOnChain, onchainScript, userPubkey, err := decodeReceiverAddress(
					receiver.Address,
				)
				if err != nil {
					return "", err
				}

				if isOnChain {
					// collaborative exit case
					// search for the output in the pool tx
					found := false
					for _, output := range ptx.UnsignedTx.TxOut {
						if bytes.Equal(output.PkScript, onchainScript) {
							if output.Value != int64(receiver.Amount) {
								return "", fmt.Errorf(
									"invalid collaborative exit output amount: got %d, want %d",
									output.Value, receiver.Amount,
								)
							}

							found = true
							break
						}
					}

					if !found {
						return "", fmt.Errorf(
							"collaborative exit output not found: %s", receiver.Address,
						)
					}

					continue
				}

				// off-chain send case
				// search for the output in congestion tree
				found := false

				// compute the receiver output taproot key
				outputTapKey, _, err := computeVtxoTaprootScript(
					userPubkey, aspPubkey, uint(unilateralExitDelay),
				)
				if err != nil {
					return "", err
				}

				leaves := congestionTree.Leaves()
				for _, leaf := range leaves {
					tx, err := psbt.NewFromRawBytes(strings.NewReader(leaf.Tx), true)
					if err != nil {
						return "", err
					}

					for _, output := range tx.UnsignedTx.TxOut {
						if len(output.PkScript) == 0 {
							continue
						}

						if bytes.Equal(
							output.PkScript[2:], schnorr.SerializePubKey(outputTapKey),
						) {
							if output.Value != int64(receiver.Amount) {
								continue
							}

							found = true
							break
						}
					}

					if found {
						break
					}
				}

				if !found {
					return "", fmt.Errorf(
						"off-chain send output not found: %s", receiver.Address,
					)
				}
			}

			fmt.Println("congestion tree validated")

			explorer := utils.NewExplorer(ctx)

			finalizePaymentRequest := &arkv1.FinalizePaymentRequest{}

			if len(vtxosToSign) > 0 {
				forfeits := e.GetForfeitTxs()
				signedForfeits := make([]string, 0)

				fmt.Print("signing forfeit txs... ")

				connectorsTxids := make([]string, 0, len(connectors))
				for _, connector := range connectors {
					p, err := psbt.NewFromRawBytes(strings.NewReader(connector), true)
					if err != nil {
						return "", err
					}
					txid := p.UnsignedTx.TxHash().String()

					connectorsTxids = append(connectorsTxids, txid)
				}

				for _, forfeit := range forfeits {
					ptx, err := psbt.NewFromRawBytes(strings.NewReader(forfeit), true)
					if err != nil {
						return "", err
					}

					for _, input := range ptx.UnsignedTx.TxIn {
						inputTxid := input.PreviousOutPoint.Hash.String()

						for _, coin := range vtxosToSign {
							// check if it contains one of the input to sign
							if inputTxid == coin.txid {
								// verify that the connector is in the connectors list
								connectorTxid := ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String()
								connectorFound := false
								for _, txid := range connectorsTxids {
									if txid == connectorTxid {
										connectorFound = true
										break
									}
								}

								if !connectorFound {
									return "", fmt.Errorf("connector txid %s not found in the connectors list", connectorTxid)
								}

								if err := signPsbt(ctx, ptx, explorer, secKey); err != nil {
									return "", err
								}

								signedPset, err := ptx.B64Encode()
								if err != nil {
									return "", err
								}

								signedForfeits = append(signedForfeits, signedPset)
							}
						}
					}
				}

				// if no forfeit txs have been signed, start pinging again and wait for the next round
				if len(vtxosToSign) > 0 && len(signedForfeits) == 0 {
					fmt.Printf("\nno forfeit txs to sign, waiting for the next round...\n")
					pingStop = nil
					for pingStop == nil {
						pingStop = ping(ctx.Context, client, pingReq)
					}
					continue
				}

				fmt.Printf("%d signed\n", len(signedForfeits))
				finalizePaymentRequest.SignedForfeitTxs = signedForfeits
			}

			if mustSignRoundTx {
				ptx, err := psbt.NewFromRawBytes(strings.NewReader(roundTx), true)
				if err != nil {
					return "", err
				}

				if err := signPsbt(ctx, ptx, explorer, secKey); err != nil {
					return "", err
				}

				signedRoundTx, err := ptx.B64Encode()
				if err != nil {
					return "", err
				}

				fmt.Println("round tx signed")
				finalizePaymentRequest.SignedRoundTx = &signedRoundTx
			}

			fmt.Print("finalizing payment... ")
			_, err = client.FinalizePayment(ctx.Context, finalizePaymentRequest)
			if err != nil {
				return "", err
			}
			fmt.Print("done.\n")
			fmt.Println("waiting for round finalization...")

			continue
		}

		if event.GetRoundFinalized() != nil {
			return event.GetRoundFinalized().GetPoolTxid(), nil
		}
	}

	return "", fmt.Errorf("stream closed unexpectedly")
}

// send 1 ping message every 5 seconds to signal to the ark service that we are still alive
// returns a function that can be used to stop the pinging
func ping(
	ctx context.Context, client arkv1.ArkServiceClient, req *arkv1.PingRequest,
) func() {
	_, err := client.Ping(ctx, req)
	if err != nil {
		return nil
	}

	ticker := time.NewTicker(5 * time.Second)

	go func(t *time.Ticker) {
		for range t.C {
			// nolint
			client.Ping(ctx, req)
		}
	}(ticker)

	return ticker.Stop
}

func isOnchainOnly(receivers []*arkv1.Output) bool {
	for _, receiver := range receivers {
		isOnChain, _, _, err := decodeReceiverAddress(receiver.Address)
		if err != nil {
			continue
		}

		if !isOnChain {
			return false
		}
	}

	return true
}
