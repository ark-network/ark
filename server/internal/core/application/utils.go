package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	log "github.com/sirupsen/logrus"
)

// onchainOutputs iterates over all the nodes' outputs in the vtxo tree and checks their onchain state
// returns the sweepable outputs as ports.SweepInput mapped by their expiration time
func findSweepableOutputs(
	ctx context.Context,
	walletSvc ports.WalletService,
	txbuilder ports.TxBuilder,
	schedulerUnit ports.TimeUnit,
	vtxoTree tree.TxTree,
) (map[int64][]ports.SweepInput, error) {
	sweepableOutputs := make(map[int64][]ports.SweepInput)
	blocktimeCache := make(map[string]int64) // txid -> blocktime / blockheight
	nodesToCheck := vtxoTree[0]              // init with the root

	for len(nodesToCheck) > 0 {
		newNodesToCheck := make([]tree.Node, 0)

		for _, node := range nodesToCheck {
			isConfirmed, height, blocktime, err := walletSvc.IsTransactionConfirmed(ctx, node.Txid)
			if err != nil {
				return nil, err
			}

			var expirationTime int64
			var sweepInput ports.SweepInput

			if !isConfirmed {
				if _, ok := blocktimeCache[node.ParentTxid]; !ok {
					isConfirmed, height, blocktime, err := walletSvc.IsTransactionConfirmed(ctx, node.ParentTxid)
					if !isConfirmed || err != nil {
						return nil, fmt.Errorf("tx %s not found", node.ParentTxid)
					}

					if schedulerUnit == ports.BlockHeight {
						blocktimeCache[node.ParentTxid] = height
					} else {
						blocktimeCache[node.ParentTxid] = blocktime
					}
				}

				var vtxoTreeExpiry *common.RelativeLocktime
				vtxoTreeExpiry, sweepInput, err = txbuilder.GetSweepInput(node)
				if err != nil {
					return nil, err
				}
				expirationTime = blocktimeCache[node.ParentTxid] + int64(vtxoTreeExpiry.Value)
			} else {
				// cache the blocktime for future use
				if schedulerUnit == ports.BlockHeight {
					blocktimeCache[node.Txid] = height
				} else {
					blocktimeCache[node.Txid] = blocktime
				}

				// if the tx is onchain, it means that the input is spent
				// add the children to the nodes in order to check them during the next iteration
				// We will return the error below, but are we going to schedule the tasks for the "children roots"?
				if !node.Leaf {
					children := vtxoTree.Children(node.Txid)
					newNodesToCheck = append(newNodesToCheck, children...)
				}
				continue
			}

			if _, ok := sweepableOutputs[expirationTime]; !ok {
				sweepableOutputs[expirationTime] = make([]ports.SweepInput, 0)
			}
			sweepableOutputs[expirationTime] = append(sweepableOutputs[expirationTime], sweepInput)
		}

		nodesToCheck = newNodesToCheck
	}

	return sweepableOutputs, nil
}

func getSpentVtxos(requests map[string]domain.TxRequest) []domain.VtxoKey {
	vtxos := make([]domain.VtxoKey, 0)
	for _, request := range requests {
		for _, vtxo := range request.Inputs {
			vtxos = append(vtxos, vtxo.VtxoKey)
		}
	}
	return vtxos
}

func decodeTx(offchainTx domain.OffchainTx) (string, []domain.VtxoKey, []domain.Vtxo, error) {
	ins := make([]domain.VtxoKey, 0, len(offchainTx.CheckpointTxs))
	for _, checkpointTx := range offchainTx.CheckpointTxs {
		checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(checkpointTx), true)
		if err != nil {
			return "", nil, nil, fmt.Errorf("failed to parse checkpoint tx: %s", err)
		}
		ins = append(ins, domain.VtxoKey{
			Txid: checkpointPtx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String(),
			VOut: checkpointPtx.UnsignedTx.TxIn[0].PreviousOutPoint.Index,
		})
	}

	ptx, err := psbt.NewFromRawBytes(strings.NewReader(offchainTx.VirtualTx), true)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to parse partial tx: %s", err)
	}
	txid := ptx.UnsignedTx.TxHash().String()

	outs := make([]domain.Vtxo, 0, len(ptx.UnsignedTx.TxOut))
	for outIndex, out := range ptx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript, tree.ANCHOR_PKSCRIPT) {
			continue
		}
		outs = append(outs, domain.Vtxo{
			VtxoKey: domain.VtxoKey{
				Txid: txid,
				VOut: uint32(outIndex),
			},
			PubKey:         hex.EncodeToString(out.PkScript[2:]),
			Amount:         uint64(out.Value),
			ExpireAt:       offchainTx.ExpiryTimestamp,
			CommitmentTxid: offchainTx.RootCommitmentTxId,
			RedeemTx:       offchainTx.VirtualTx,
			CreatedAt:      offchainTx.EndingTimestamp,
		})
	}

	return txid, ins, outs, nil
}

func newBoardingInput(
	tx wire.MsgTx,
	input ports.Input,
	serverPubKey *secp256k1.PublicKey,
	boardingExitDelay common.RelativeLocktime,
) (*ports.BoardingInput, error) {
	if len(tx.TxOut) <= int(input.VOut) {
		return nil, fmt.Errorf("output not found")
	}

	output := tx.TxOut[input.VOut]

	boardingScript, err := tree.ParseVtxoScript(input.Tapscripts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse boarding utxo taproot tree: %s", err)
	}

	tapKey, _, err := boardingScript.TapTree()
	if err != nil {
		return nil, fmt.Errorf("failed to get taproot key: %s", err)
	}

	expectedScriptPubkey, err := common.P2TRScript(tapKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get script pubkey: %s", err)
	}

	if !bytes.Equal(output.PkScript, expectedScriptPubkey) {
		return nil, fmt.Errorf(
			"invalid boarding utxo taproot key: got %x expected %x",
			output.PkScript, expectedScriptPubkey,
		)
	}

	if err := boardingScript.Validate(serverPubKey, boardingExitDelay); err != nil {
		return nil, err
	}

	return &ports.BoardingInput{
		Amount: uint64(output.Value),
		Input:  input,
	}, nil
}

func calcNextMarketHour(marketHourStartTime, marketHourEndTime time.Time, period, marketHourDelta time.Duration, now time.Time) (time.Time, time.Time, error) {
	// Validate input parameters
	if period <= 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("period must be greater than 0")
	}
	if !marketHourEndTime.After(marketHourStartTime) {
		return time.Time{}, time.Time{}, fmt.Errorf("market hour end time must be after start time")
	}

	// Calculate the duration of the market hour
	duration := marketHourEndTime.Sub(marketHourStartTime)

	// Calculate the number of periods since the initial marketHourStartTime
	elapsed := now.Sub(marketHourStartTime)
	var n int64
	if elapsed >= 0 {
		n = int64(elapsed / period)
	} else {
		n = int64((elapsed - period + 1) / period)
	}

	// Calculate the current market hour start and end times
	currentStartTime := marketHourStartTime.Add(time.Duration(n) * period)
	currentEndTime := currentStartTime.Add(duration)

	// Adjust if now is before the currentStartTime
	if now.Before(currentStartTime) {
		n -= 1
		currentStartTime = marketHourStartTime.Add(time.Duration(n) * period)
		currentEndTime = currentStartTime.Add(duration)
	}

	timeUntilEnd := currentEndTime.Sub(now)

	if !now.Before(currentStartTime) && now.Before(currentEndTime) && timeUntilEnd >= marketHourDelta {
		// Return the current market hour
		return currentStartTime, currentEndTime, nil
	} else {
		// Move to the next market hour
		n += 1
		nextStartTime := marketHourStartTime.Add(time.Duration(n) * period)
		nextEndTime := nextStartTime.Add(duration)
		return nextStartTime, nextEndTime, nil
	}
}

func getNewVtxosFromRound(round *domain.Round) []domain.Vtxo {
	if len(round.VtxoTree) <= 0 {
		return nil
	}

	now := time.Now()
	createdAt := now.Unix()
	expireAt := round.ExpiryTimestamp()

	leaves := round.VtxoTree.Leaves()
	vtxos := make([]domain.Vtxo, 0)
	for _, node := range leaves {
		tx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
		if err != nil {
			log.WithError(err).Warn("failed to parse tx")
			continue
		}
		for i, out := range tx.UnsignedTx.TxOut {
			if bytes.Equal(out.PkScript, tree.ANCHOR_PKSCRIPT) {
				continue
			}

			vtxoTapKey, err := schnorr.ParsePubKey(out.PkScript[2:])
			if err != nil {
				log.WithError(err).Warn("failed to parse vtxo tap key")
				continue
			}

			vtxoPubkey := hex.EncodeToString(schnorr.SerializePubKey(vtxoTapKey))
			vtxos = append(vtxos, domain.Vtxo{
				VtxoKey:        domain.VtxoKey{Txid: node.Txid, VOut: uint32(i)},
				PubKey:         vtxoPubkey,
				Amount:         uint64(out.Value),
				CommitmentTxid: round.Txid,
				CreatedAt:      createdAt,
				ExpireAt:       expireAt,
			})
		}
	}
	return vtxos
}
