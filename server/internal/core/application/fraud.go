package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	log "github.com/sirupsen/logrus"
)

func (s *covenantlessService) reactToFraud(ctx context.Context, vtxo domain.Vtxo, mutx *sync.Mutex) error {
	mutx.Lock()
	defer mutx.Unlock()

	round, err := s.repoManager.Rounds().GetRoundWithTxid(ctx, vtxo.SpentBy)
	if err != nil {
		// if spentBy is not a round, it means the utxo is spent by an offchain tx
		// react by broadcasting the next checkpoint tx
		if err := s.broadcastCheckpointTx(ctx, vtxo); err != nil {
			return fmt.Errorf("failed to broadcast checkpoint tx: %s", err)
		}

		return nil
	}

	// if the round is found, it means the vtxo has been settled
	// react by broadcasting the associated forfeit tx
	if err := s.broadcastForfeitTx(ctx, round, vtxo.VtxoKey); err != nil {
		return fmt.Errorf("failed to broadcast forfeit tx: %s", err)
	}

	return nil
}

func (s *covenantlessService) broadcastCheckpointTx(ctx context.Context, vtxo domain.Vtxo) error {
	// retrieve the first vtxo created by the spending tx
	vtxos, err := s.repoManager.Vtxos().GetVtxos(ctx, []domain.VtxoKey{
		{Txid: vtxo.SpentBy, VOut: 0},
	})
	if err != nil || len(vtxos) <= 0 {
		return fmt.Errorf("failed to retrieve round: %s", err)
	}

	storedVtxo := vtxos[0]
	if storedVtxo.Redeemed {
		// virtual tx is already onchain
		// no need to broadcast the checkpoint tx
		return nil
	}

	log.Debugf("vtxo %s:%d has been spent by out of round transaction", vtxo.Txid, vtxo.VOut)

	offchainTxid := storedVtxo.Txid

	offchainTx, err := s.repoManager.OffchainTxs().GetOffchainTx(ctx, offchainTxid)
	if err != nil {
		return fmt.Errorf("failed to retrieve offchain tx: %s", err)
	}

	checkpointPsbt := ""

	for _, b64 := range offchainTx.CheckpointTxs {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
		if err != nil {
			return fmt.Errorf("failed to deserialize checkpoint tx: %s", err)
		}

		vtxoInput := ptx.UnsignedTx.TxIn[0]
		if vtxoInput.PreviousOutPoint.Hash.String() == vtxo.Txid &&
			vtxoInput.PreviousOutPoint.Index == vtxo.VOut {
			checkpointPsbt = b64
			break
		}
	}

	parent, err := s.builder.FinalizeAndExtract(checkpointPsbt)
	if err != nil {
		return fmt.Errorf("failed to finalize checkpoint tx: %s", err)
	}

	var checkpointTx wire.MsgTx
	if err := checkpointTx.Deserialize(hex.NewDecoder(strings.NewReader(parent))); err != nil {
		return fmt.Errorf("failed to deserialize checkpoint tx: %s", err)
	}

	child, err := s.bumpAnchorTx(ctx, &checkpointTx)
	if err != nil {
		return fmt.Errorf("failed to bump checkpoint tx: %s", err)
	}

	if _, err := s.wallet.BroadcastTransaction(ctx, parent, child); err != nil {
		return fmt.Errorf("failed to broadcast checkpoint tx: %s", err)
	}

	log.Debugf("broadcasted checkpoint tx %s", checkpointTx.TxHash().String())
	return nil
}

func (s *covenantlessService) broadcastForfeitTx(ctx context.Context, round *domain.Round, vtxo domain.VtxoKey) error {
	forfeitTx, err := findForfeitTx(round.ForfeitTxs, vtxo)
	if err != nil {
		return fmt.Errorf("failed to find forfeit tx: %s", err)
	}

	if len(forfeitTx.UnsignedTx.TxIn) <= 0 {
		return fmt.Errorf("invalid forfeit tx: %s", forfeitTx.UnsignedTx.TxHash().String())
	}

	connector := forfeitTx.UnsignedTx.TxIn[0]
	connectorOutpoint := txOutpoint{
		connector.PreviousOutPoint.Hash.String(),
		connector.PreviousOutPoint.Index,
	}

	if err := s.broadcastConnectorBranch(ctx, round.Connectors, connectorOutpoint); err != nil {
		return fmt.Errorf("failed to broadcast connector branch: %s", err)
	}

	if err := s.wallet.LockConnectorUtxos(ctx, []ports.TxOutpoint{connectorOutpoint}); err != nil {
		return fmt.Errorf("failed to lock connector utxos: %s", err)
	}

	forfeitTxB64, err := forfeitTx.B64Encode()
	if err != nil {
		return fmt.Errorf("failed to encode forfeit tx: %s", err)
	}

	signedForfeitTx, err := s.wallet.SignTransactionTapscript(ctx, forfeitTxB64, nil)
	if err != nil {
		return fmt.Errorf("failed to sign forfeit tx: %s", err)
	}

	forfeitTxHex, err := s.builder.FinalizeAndExtract(signedForfeitTx)
	if err != nil {
		return fmt.Errorf("failed to finalize forfeit tx: %s", err)
	}

	var forfeit wire.MsgTx
	if err := forfeit.Deserialize(hex.NewDecoder(strings.NewReader(forfeitTxHex))); err != nil {
		return fmt.Errorf("failed to deserialize forfeit tx: %s", err)
	}

	childForfeit, err := s.bumpAnchorTx(ctx, &forfeit)
	if err != nil {
		return fmt.Errorf("failed to bump forfeit tx: %s", err)
	}

	if _, err = s.wallet.BroadcastTransaction(ctx, forfeitTxHex, childForfeit); err != nil {
		return fmt.Errorf("failed to broadcast forfeit tx: %s", err)
	}

	log.Debugf("broadcasted forfeit tx %s", forfeit.TxHash().String())
	return nil
}

func (s *covenantlessService) broadcastConnectorBranch(ctx context.Context, connectorTree tree.TxTree, connectorOutpoint txOutpoint) error {
	// compute, sign and broadcast the branch txs until the connector outpoint is created
	branch, err := connectorTree.Branch(connectorOutpoint.txid)
	if err != nil {
		return fmt.Errorf("failed to get branch of connector: %s", err)
	}

	for _, node := range branch {
		_, err := s.wallet.GetTransaction(ctx, node.Txid)
		// if err, it means the tx is offchain, must be broadcasted
		if err != nil {
			parent, err := s.wallet.SignTransaction(ctx, node.Tx, true)
			if err != nil {
				return fmt.Errorf("failed to sign tx: %s", err)
			}

			var parentTx wire.MsgTx
			if err := parentTx.Deserialize(hex.NewDecoder(strings.NewReader(parent))); err != nil {
				return fmt.Errorf("failed to deserialize tx: %s", err)
			}

			child, err := s.bumpAnchorTx(ctx, &parentTx)
			if err != nil {
				return fmt.Errorf("failed to bump anchor tx: %s", err)
			}

			_, err = s.wallet.BroadcastTransaction(ctx, parent, child)
			if err != nil {
				return fmt.Errorf("failed to broadcast transaction: %s", err)
			}
			log.Debugf("broadcasted connector branch tx %s", node.Txid)

			if err := s.wallet.WaitForSync(ctx, node.Txid); err != nil {
				return fmt.Errorf("failed to wait for sync: %s", err)
			}

			s.waitForConfirmation(ctx, node.Txid)
		}
	}

	return nil
}

// bumpAnchorTx is crafting and signing a transaction bumping the fees for a given tx with P2A output
func (s *covenantlessService) bumpAnchorTx(ctx context.Context, parent *wire.MsgTx) (string, error) {
	anchor, err := tree.FindAnchorOutpoint(parent)
	if err != nil {
		return "", err
	}

	// estimate for the size of the bump transaction
	weightEstimator := input.TxWeightEstimator{}

	// WeightEstimator doesn't support P2A size, using P2WSH will lead to a small overestimation
	// TODO use the exact P2A size
	weightEstimator.AddNestedP2WSHInput(lntypes.VByte(3).ToWU())

	// We assume only one UTXO will be selected to have a correct estimation
	weightEstimator.AddTaprootKeySpendInput(txscript.SigHashDefault)
	weightEstimator.AddP2TROutput()

	childVSize := weightEstimator.Weight().ToVB()

	packageSize := childVSize + computeVSize(parent)
	feeRate, err := s.wallet.FeeRate(ctx)
	if err != nil {
		return "", err
	}

	fees := chainfee.SatPerKVByte(feeRate).FeeForVSize(packageSize)

	selectedCoins, changeAmount, err := s.wallet.SelectUtxos(ctx, "", uint64(fees.ToUnit(btcutil.AmountSatoshi)), true)
	if err != nil {
		return "", err
	}

	addresses, err := s.wallet.DeriveAddresses(ctx, 1)
	if err != nil {
		return "", err
	}

	addr, err := btcutil.DecodeAddress(addresses[0], nil)
	if err != nil {
		return "", err
	}

	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return "", err
	}

	inputs := []*wire.OutPoint{anchor}
	sequences := []uint32{
		wire.MaxTxInSequenceNum,
	}

	for _, utxo := range selectedCoins {
		txid, err := chainhash.NewHashFromStr(utxo.GetTxid())
		if err != nil {
			return "", err
		}
		inputs = append(inputs, &wire.OutPoint{
			Hash:  *txid,
			Index: utxo.GetIndex(),
		})
		sequences = append(sequences, wire.MaxTxInSequenceNum)
	}

	ptx, err := psbt.New(
		inputs,
		[]*wire.TxOut{
			{
				Value:    int64(changeAmount),
				PkScript: pkScript,
			},
		},
		3,
		0,
		sequences,
	)
	if err != nil {
		return "", err
	}

	ptx.Inputs[0].WitnessUtxo = tree.AnchorOutput()

	b64, err := ptx.B64Encode()
	if err != nil {
		return "", err
	}

	tx, err := s.wallet.SignTransaction(ctx, b64, false)
	if err != nil {
		return "", err
	}

	signedPtx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", err
	}

	for inIndex := range signedPtx.Inputs[1:] {
		if _, err := psbt.MaybeFinalize(signedPtx, inIndex+1); err != nil {
			return "", err
		}
	}

	childTx, err := tree.ExtractWithAnchors(signedPtx)
	if err != nil {
		return "", err
	}

	var serializedTx bytes.Buffer
	if err := childTx.Serialize(&serializedTx); err != nil {
		return "", err
	}

	return hex.EncodeToString(serializedTx.Bytes()), nil
}

func (s *covenantlessService) waitForConfirmation(ctx context.Context, txid string) {
	tickerInterval := 1 * time.Minute
	if s.network.Name == common.BitcoinRegTest.Name {
		tickerInterval = 1 * time.Second
	}
	ticker := time.NewTicker(tickerInterval)
	defer ticker.Stop()

	for range ticker.C {
		if confirmed, _, _, _ := s.wallet.IsTransactionConfirmed(ctx, txid); confirmed {
			return
		}
	}
}

func findForfeitTx(
	forfeits []domain.ForfeitTx, vtxo domain.VtxoKey,
) (*psbt.Packet, error) {
	for _, forfeit := range forfeits {
		forfeitTx, err := psbt.NewFromRawBytes(strings.NewReader(forfeit.Tx), true)
		if err != nil {
			return nil, err
		}

		vtxoInput := forfeitTx.UnsignedTx.TxIn[1]

		if vtxoInput.PreviousOutPoint.Hash.String() == vtxo.Txid &&
			vtxoInput.PreviousOutPoint.Index == vtxo.VOut {
			return forfeitTx, nil
		}
	}

	return nil, fmt.Errorf("forfeit tx not found")
}

func computeVSize(tx *wire.MsgTx) lntypes.VByte {
	baseSize := tx.SerializeSizeStripped()
	totalSize := tx.SerializeSize() // including witness
	weight := totalSize + baseSize*3
	return lntypes.WeightUnit(uint64(weight)).ToVB()
}
