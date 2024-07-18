package arksdk

import (
	"bytes"
	"context"
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-elements/psetv2"
)

func (a *arkClient) handleRoundStream(
	ctx context.Context,
	paymentID string,
	vtxosToSign []vtxo,
	receivers []*arkv1.Output,
) (string, error) {
	eventStream, err := a.innerClient.getEventStream(ctx, paymentID, &arkv1.GetEventStreamRequest{})
	if err != nil {
		return "", err
	}

	var pingStop func()
	pingReq := &arkv1.PingRequest{
		PaymentId: paymentID,
	}
	for pingStop == nil {
		pingStop = a.ping(ctx, pingReq)
	}

	defer pingStop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case event := <-eventStream.eventResp:
			if e := event.GetRoundFailed(); e != nil {
				pingStop()
				return "", fmt.Errorf("round failed: %s", e.GetReason())
			}

			if e := event.GetRoundFinalization(); e != nil {
				pingStop()
				log.Info("a round finalization started")

				signedForfeitTxs, err := a.handleRoundFinalization(
					e, vtxosToSign, receivers,
				)
				if err != nil {
					return "", err
				}

				if len(signedForfeitTxs) <= 0 {
					log.Info("no forfeit txs to sign, waiting for the next round")
					continue
				}

				log.Info("finalizing payment... ")
				_, err = a.innerClient.finalizePayment(ctx, &arkv1.FinalizePaymentRequest{
					SignedForfeitTxs: signedForfeitTxs,
				})
				if err != nil {
					return "", err
				}

				log.Info("done.")
				log.Info("waiting for round finalization...")
			}

			if event.GetRoundFinalized() != nil {
				return event.GetRoundFinalized().GetPoolTxid(), nil
			}
		case e := <-eventStream.err:
			return "", e
		}
	}
}

func (a *arkClient) handleRoundFinalization(
	finalization *arkv1.RoundFinalizationEvent,
	vtxosToSign []vtxo,
	receivers []*arkv1.Output,
) ([]string, error) {
	if err := a.validateCongestionTree(finalization, receivers); err != nil {
		return nil, fmt.Errorf("failed to verify congestion tree: %s", err)
	}

	return a.loopAndSign(
		finalization.GetForfeitTxs(), vtxosToSign, finalization.GetConnectors(),
	)
}

func (a *arkClient) validateCongestionTree(
	finalization *arkv1.RoundFinalizationEvent,
	receivers []*arkv1.Output,
) error {
	poolTx := finalization.GetPoolTx()
	ptx, err := psetv2.NewPsetFromBase64(poolTx)
	if err != nil {
		return err
	}

	congestionTree, err := toCongestionTree(finalization.GetCongestionTree())
	if err != nil {
		return err
	}

	connectors := finalization.GetConnectors()

	aspPubkey, err := secp256k1.ParsePubKey(a.aspPubKey)
	if err != nil {
		return err
	}

	if !isOnchainOnly(receivers) {
		if err := tree.ValidateCongestionTree(
			congestionTree, poolTx, aspPubkey, int64(a.roundLifeTime),
		); err != nil {
			return err
		}
	}

	if err := common.ValidateConnectors(poolTx, connectors); err != nil {
		return err
	}

	if err := a.validateReceivers(ptx, receivers, &congestionTree, aspPubkey); err != nil {
		return err
	}

	log.Infoln("congestion tree validated")

	return nil
}

func (a *arkClient) validateReceivers(
	ptx *psetv2.Pset,
	receivers []*arkv1.Output,
	congestionTree *tree.CongestionTree,
	aspPubkey *secp256k1.PublicKey,
) error {
	for _, receiver := range receivers {
		isOnChain, onchainScript, userPubkey, err := decodeReceiverAddress(receiver.Address)
		if err != nil {
			return err
		}

		if isOnChain {
			if err := a.validateOnChainReceiver(ptx, receiver, onchainScript); err != nil {
				return err
			}
		} else {
			if err := a.validateOffChainReceiver(congestionTree, receiver, userPubkey, aspPubkey); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *arkClient) validateOnChainReceiver(
	ptx *psetv2.Pset,
	receiver *arkv1.Output,
	onchainScript []byte,
) error {
	found := false
	for _, output := range ptx.Outputs {
		if bytes.Equal(output.Script, onchainScript) {
			if output.Value != receiver.Amount {
				return fmt.Errorf(
					"invalid collaborative exit output amount: got %d, want %d",
					output.Value, receiver.Amount,
				)
			}
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("collaborative exit output not found: %s", receiver.Address)
	}
	return nil
}

func (a *arkClient) validateOffChainReceiver(
	congestionTree *tree.CongestionTree,
	receiver *arkv1.Output,
	userPubkey, aspPubkey *secp256k1.PublicKey,
) error {
	found := false
	outputTapKey, _, err := computeVtxoTaprootScript(
		userPubkey, aspPubkey, uint(a.unilateralExitDelay),
	)
	if err != nil {
		return err
	}

	leaves := congestionTree.Leaves()
	for _, leaf := range leaves {
		tx, err := psetv2.NewPsetFromBase64(leaf.Tx)
		if err != nil {
			return err
		}

		for _, output := range tx.Outputs {
			if len(output.Script) == 0 {
				continue
			}
			if bytes.Equal(output.Script[2:], schnorr.SerializePubKey(outputTapKey)) {
				if output.Value == receiver.Amount {
					found = true
					break
				}
			}
		}

		if found {
			break
		}
	}

	if !found {
		return fmt.Errorf("off-chain send output not found: %s", receiver.Address)
	}
	return nil
}

func (a *arkClient) loopAndSign(
	forfeitTxs []string, vtxosToSign []vtxo, connectors []string,
) ([]string, error) {
	signedForfeits := make([]string, 0)

	connectorsTxids := make([]string, 0, len(connectors))
	for _, connector := range connectors {
		p, _ := psetv2.NewPsetFromBase64(connector)
		utx, _ := p.UnsignedTx()
		txid := utx.TxHash().String()
		connectorsTxids = append(connectorsTxids, txid)
	}

	for _, forfeitTx := range forfeitTxs {
		pset, err := psetv2.NewPsetFromBase64(forfeitTx)
		if err != nil {
			return nil, err
		}

		for _, input := range pset.Inputs {
			inputTxid := chainhash.Hash(input.PreviousTxid).String()
			for _, coin := range vtxosToSign {
				if inputTxid == coin.txid {
					signedPset, err := a.signForfeitTx(forfeitTx, pset, connectorsTxids)
					if err != nil {
						return nil, err
					}
					signedForfeits = append(signedForfeits, signedPset)
				}
			}
		}
	}

	return signedForfeits, nil
}

func (a *arkClient) signForfeitTx(
	txStr string, tx *psetv2.Pset, connectorsTxids []string,
) (string, error) {
	connectorTxid := chainhash.Hash(tx.Inputs[0].PreviousTxid).String()
	connectorFound := false
	for _, id := range connectorsTxids {
		if id == connectorTxid {
			connectorFound = true
			break
		}
	}
	if !connectorFound {
		return "", fmt.Errorf("connector txid %s not found in the connectors list", connectorTxid)
	}

	return a.wallet.SignTransaction(a.explorerSvc, txStr)
}
