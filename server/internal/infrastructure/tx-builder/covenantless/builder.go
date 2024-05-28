package txbuilder

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	connectorAmount = uint64(1000)
	dustLimit       = uint64(1000)
)

type txBuilder struct {
	wallet        ports.WalletService
	net           *chaincfg.Params
	roundLifetime int64 // in seconds
	exitDelay     int64 // in seconds
}

func NewTxBuilder(
	wallet ports.WalletService, net *chaincfg.Params, roundLifetime int64, exitDelay int64,
) ports.TxBuilder {
	return &txBuilder{wallet, net, roundLifetime, exitDelay}
}

func (b *txBuilder) GetVtxoScript(userPubkey, aspPubkey *secp256k1.PublicKey) ([]byte, error) {
	outputScript, _, err := b.getLeafScriptAndTree(userPubkey, aspPubkey)
	if err != nil {
		return nil, err
	}
	return outputScript, nil
}

func (b *txBuilder) BuildSweepTx(inputs []ports.SweepInput) (signedSweepTx string, err error) {
	sweepPset, err := sweepTransaction(
		b.wallet,
		inputs,
	)
	if err != nil {
		return "", err
	}

	sweepPsetBase64, err := sweepPset.B64Encode()
	if err != nil {
		return "", err
	}

	ctx := context.Background()
	signedSweepPsetB64, err := b.wallet.SignPsetWithKey(ctx, sweepPsetBase64, nil)
	if err != nil {
		return "", err
	}

	signedPsbt, err := psbt.NewFromRawBytes(strings.NewReader(signedSweepPsetB64), true)
	if err != nil {
		return "", err
	}

	for i := range inputs {
		if err := psbt.Finalize(signedPsbt, i); err != nil {
			return "", err
		}
	}

	tx, err := psbt.Extract(signedPsbt)
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)

	if err := tx.Serialize(buf); err != nil {
		return "", err
	}

	return hex.EncodeToString(buf.Bytes()), nil
}

func (b *txBuilder) BuildForfeitTxs(
	aspPubkey *secp256k1.PublicKey, poolTx string, payments []domain.Payment, minRelayFee uint64,
) (connectors []string, forfeitTxs []string, err error) {
	connectorPkScript, err := b.getConnectorPkScript(poolTx)
	if err != nil {
		return nil, nil, err
	}

	connectorTxs, err := b.createConnectors(poolTx, payments, connectorPkScript, minRelayFee)
	if err != nil {
		return nil, nil, err
	}

	forfeitTxs, err = b.createForfeitTxs(aspPubkey, payments, connectorTxs, minRelayFee)
	if err != nil {
		return nil, nil, err
	}

	for _, tx := range connectorTxs {
		buf, _ := tx.B64Encode()
		connectors = append(connectors, buf)
	}
	return connectors, forfeitTxs, nil
}

func (b *txBuilder) BuildPoolTx(
	aspPubkey *secp256k1.PublicKey, payments []domain.Payment, minRelayFee uint64,
) (poolTx string, congestionTree tree.CongestionTree, connectorAddress string, err error) {
	var sharedOutputScript []byte
	var sharedOutputAmount int64

	var senders []*secp256k1.PublicKey
	senders, err = getCosigners(payments)
	if err != nil {
		return
	}

	cosigners := append(senders, aspPubkey)
	receivers := getOffchainReceivers(payments)

	if !isOnchainOnly(payments) {
		sharedOutputScript, sharedOutputAmount, err = bitcointree.CraftSharedOutput(
			cosigners, aspPubkey, receivers, minRelayFee, b.roundLifetime, b.exitDelay,
		)
		if err != nil {
			return
		}
	}

	connectorAddress, err = b.wallet.DeriveConnectorAddress(context.Background())
	if err != nil {
		return
	}

	ptx, err := b.createPoolTx(
		sharedOutputAmount, sharedOutputScript, payments, aspPubkey, connectorAddress, minRelayFee,
	)
	if err != nil {
		return
	}

	poolTx, err = ptx.B64Encode()
	if err != nil {
		return
	}

	if !isOnchainOnly(payments) {
		initialOutpoint := &wire.OutPoint{
			Hash:  ptx.UnsignedTx.TxHash(),
			Index: 0,
		}

		congestionTree, err = bitcointree.CraftCongestionTree(
			initialOutpoint, cosigners, aspPubkey, receivers, minRelayFee, b.roundLifetime, b.exitDelay,
		)
		if err != nil {
			return
		}
	}

	return
}

func (b *txBuilder) getLeafScriptAndTree(
	userPubkey, aspPubkey *secp256k1.PublicKey,
) ([]byte, *txscript.IndexedTapScriptTree, error) {
	redeemClosure := &bitcointree.CSVSigClosure{
		Pubkey:  userPubkey,
		Seconds: uint(b.exitDelay),
	}

	redeemLeaf, err := redeemClosure.Leaf()
	if err != nil {
		return nil, nil, err
	}

	forfeitClosure := &bitcointree.ForfeitClosure{
		Pubkey:    userPubkey,
		AspPubkey: aspPubkey,
	}

	forfeitLeaf, err := forfeitClosure.Leaf()
	if err != nil {
		return nil, nil, err
	}

	taprootTree := txscript.AssembleTaprootScriptTree(
		*redeemLeaf, *forfeitLeaf,
	)

	root := taprootTree.RootNode.TapHash()
	unspendableKey := tree.UnspendableKey()
	taprootKey := txscript.ComputeTaprootOutputKey(unspendableKey, root[:])

	outputScript, err := taprootOutputScript(taprootKey)
	if err != nil {
		return nil, nil, err
	}

	return outputScript, taprootTree, nil
}

func (b *txBuilder) createPoolTx(
	sharedOutputAmount int64, sharedOutputScript []byte,
	payments []domain.Payment, aspPubKey *secp256k1.PublicKey, connectorAddress string, minRelayFee uint64,
) (*psbt.Packet, error) {
	aspScript, err := p2trScript(aspPubKey, b.net)
	if err != nil {
		return nil, err
	}

	connectorAddr, err := btcutil.DecodeAddress(connectorAddress, b.net)
	if err != nil {
		return nil, err
	}

	connectorScript, err := txscript.PayToAddrScript(connectorAddr)
	if err != nil {
		return nil, err
	}

	receivers := getOnchainReceivers(payments)
	nbOfInputs := countSpentVtxos(payments)
	connectorsAmount := (connectorAmount + minRelayFee) * nbOfInputs
	if nbOfInputs > 1 {
		connectorsAmount -= minRelayFee
	}
	targetAmount := connectorsAmount

	outputs := make([]*wire.TxOut, 0)

	if sharedOutputScript != nil && sharedOutputAmount > 0 {
		targetAmount += uint64(sharedOutputAmount)

		outputs = append(outputs, &wire.TxOut{
			Value:    sharedOutputAmount,
			PkScript: sharedOutputScript,
		})
	}

	outputs = append(outputs, &wire.TxOut{
		Value:    int64(connectorAmount),
		PkScript: connectorScript,
	})

	for _, receiver := range receivers {
		targetAmount += receiver.Amount

		receiverAddr, err := btcutil.DecodeAddress(receiver.OnchainAddress, b.net)
		if err != nil {
			return nil, err
		}

		receiverScript, err := txscript.PayToAddrScript(receiverAddr)
		if err != nil {
			return nil, err
		}

		outputs = append(outputs, &wire.TxOut{
			Value:    int64(receiver.Amount),
			PkScript: receiverScript,
		})
	}

	ctx := context.Background()
	utxos, change, err := b.wallet.SelectUtxos(ctx, "", targetAmount)
	if err != nil {
		return nil, err
	}

	var dust uint64
	if change > 0 {
		if change < dustLimit {
			dust = change
			change = 0
		} else {
			outputs = append(outputs, &wire.TxOut{
				Value:    int64(change),
				PkScript: aspScript,
			})
		}
	}

	ins := make([]*wire.OutPoint, 0)

	for _, utxo := range utxos {
		txhash, err := chainhash.NewHashFromStr(utxo.GetTxid())
		if err != nil {
			return nil, err
		}

		ins = append(ins, &wire.OutPoint{
			Hash:  *txhash,
			Index: utxo.GetIndex(),
		})
	}

	ptx, err := psbt.New(ins, outputs, 2, 0, []uint32{wire.MaxTxInSequenceNum})
	if err != nil {
		return nil, err
	}

	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return nil, err
	}
	for _, utxo := range utxos {
		script, err := hex.DecodeString(utxo.GetScript())
		if err != nil {
			return nil, err
		}

		if err := updater.AddInWitnessUtxo(&wire.TxOut{
			Value:    int64(utxo.GetValue()),
			PkScript: script,
		}, 0); err != nil {
			return nil, err
		}
	}

	b64, err := ptx.B64Encode()
	if err != nil {
		return nil, err
	}

	feeAmount, err := b.wallet.EstimateFees(ctx, b64)
	if err != nil {
		return nil, err
	}

	if dust > feeAmount {
		feeAmount = dust
	} else {
		feeAmount += dust
	}

	if dust == 0 {
		if feeAmount == change {
			// fees = change, remove change output
			ptx.UnsignedTx.TxOut = ptx.UnsignedTx.TxOut[:len(ptx.UnsignedTx.TxOut)-1]
			ptx.Outputs = ptx.Outputs[:len(ptx.Outputs)-1]
		} else if feeAmount < change {
			// change covers the fees, reduce change amount
			ptx.UnsignedTx.TxOut[len(ptx.Outputs)-1].Value = int64(change - feeAmount)
		} else {
			// change is not enough to cover fees, re-select utxos
			if change > 0 {
				// remove change output if present
				ptx.UnsignedTx.TxOut = ptx.UnsignedTx.TxOut[:len(ptx.UnsignedTx.TxOut)-1]
				ptx.Outputs = ptx.Outputs[:len(ptx.Outputs)-1]
			}
			newUtxos, change, err := b.wallet.SelectUtxos(ctx, "", feeAmount-change)
			if err != nil {
				return nil, err
			}

			if change > 0 {
				ptx.UnsignedTx.AddTxOut(&wire.TxOut{
					Value:    int64(change),
					PkScript: aspScript,
				})
				ptx.Outputs = append(ptx.Outputs, psbt.POutput{})
			}

			for _, utxo := range newUtxos {
				txhash, err := chainhash.NewHashFromStr(utxo.GetTxid())
				if err != nil {
					return nil, err
				}

				outpoint := &wire.OutPoint{
					Hash:  *txhash,
					Index: utxo.GetIndex(),
				}

				ptx.UnsignedTx.AddTxIn(wire.NewTxIn(outpoint, nil, nil))
				ptx.Inputs = append(ptx.Inputs, psbt.PInput{})

				scriptBytes, err := hex.DecodeString(utxo.GetScript())
				if err != nil {
					return nil, err
				}

				if err := updater.AddInWitnessUtxo(
					&wire.TxOut{
						Value:    int64(utxo.GetValue()),
						PkScript: scriptBytes,
					},
					len(ptx.UnsignedTx.TxIn)-1,
				); err != nil {
					return nil, err
				}
			}

		}
	} else if feeAmount-dust > 0 {
		newUtxos, change, err := b.wallet.SelectUtxos(ctx, "", feeAmount-dust)
		if err != nil {
			return nil, err
		}

		if change > 0 {
			if change > dustLimit {
				ptx.UnsignedTx.AddTxOut(&wire.TxOut{
					Value:    int64(change),
					PkScript: aspScript,
				})
				ptx.Outputs = append(ptx.Outputs, psbt.POutput{})
			}
		}

		for _, utxo := range newUtxos {
			txhash, err := chainhash.NewHashFromStr(utxo.GetTxid())
			if err != nil {
				return nil, err
			}

			outpoint := &wire.OutPoint{
				Hash:  *txhash,
				Index: utxo.GetIndex(),
			}

			ptx.UnsignedTx.AddTxIn(wire.NewTxIn(outpoint, nil, nil))
			ptx.Inputs = append(ptx.Inputs, psbt.PInput{})

			scriptBytes, err := hex.DecodeString(utxo.GetScript())
			if err != nil {
				return nil, err
			}

			if err := updater.AddInWitnessUtxo(
				&wire.TxOut{
					Value:    int64(utxo.GetValue()),
					PkScript: scriptBytes,
				},
				len(ptx.UnsignedTx.TxIn)-1,
			); err != nil {
				return nil, err
			}
		}
	}

	return ptx, nil
}

func (b *txBuilder) createConnectors(
	poolTx string, payments []domain.Payment, connectorScript []byte, minRelayFee uint64,
) ([]*psbt.Packet, error) {
	partialTx, err := psbt.NewFromRawBytes(strings.NewReader(poolTx), true)
	if err != nil {
		return nil, err
	}

	connectorOutput := &wire.TxOut{
		PkScript: connectorScript,
		Value:    int64(connectorAmount),
	}

	numberOfConnectors := countSpentVtxos(payments)

	previousInput := &wire.OutPoint{
		Hash:  partialTx.UnsignedTx.TxHash(),
		Index: 1,
	}

	if numberOfConnectors == 1 {
		outputs := []*wire.TxOut{connectorOutput}
		connectorTx, err := craftConnectorTx(previousInput, connectorScript, outputs, minRelayFee)
		if err != nil {
			return nil, err
		}

		return []*psbt.Packet{connectorTx}, nil
	}

	totalConnectorAmount := (connectorAmount + minRelayFee) * numberOfConnectors
	if numberOfConnectors > 1 {
		totalConnectorAmount -= minRelayFee
	}

	connectors := make([]*psbt.Packet, 0, numberOfConnectors-1)
	for i := uint64(0); i < numberOfConnectors-1; i++ {
		outputs := []*wire.TxOut{connectorOutput}
		totalConnectorAmount -= connectorAmount
		totalConnectorAmount -= minRelayFee
		if totalConnectorAmount > 0 {
			outputs = append(outputs, &wire.TxOut{
				PkScript: connectorScript,
				Value:    int64(totalConnectorAmount),
			})
		}
		connectorTx, err := craftConnectorTx(previousInput, connectorScript, outputs, minRelayFee)
		if err != nil {
			return nil, err
		}

		previousInput = &wire.OutPoint{
			Hash:  connectorTx.UnsignedTx.TxHash(),
			Index: 1,
		}

		connectors = append(connectors, connectorTx)
	}

	return connectors, nil
}

func (b *txBuilder) createForfeitTxs(
	aspPubkey *secp256k1.PublicKey, payments []domain.Payment, connectors []*psbt.Packet, minRelayFee uint64,
) ([]string, error) {
	aspScript, err := p2trScript(aspPubkey, b.net)
	if err != nil {
		return nil, err
	}

	forfeitTxs := make([]string, 0)
	for _, payment := range payments {
		for _, vtxo := range payment.Inputs {
			pubkeyBytes, err := hex.DecodeString(vtxo.Pubkey)
			if err != nil {
				return nil, fmt.Errorf("failed to decode pubkey: %s", err)
			}

			vtxoPubkey, err := secp256k1.ParsePubKey(pubkeyBytes)
			if err != nil {
				return nil, err
			}

			vtxoScript, vtxoTaprootTree, err := b.getLeafScriptAndTree(vtxoPubkey, aspPubkey)
			if err != nil {
				return nil, err
			}

			var forfeitProof *txscript.TapscriptProof

			for _, proof := range vtxoTaprootTree.LeafMerkleProofs {
				isForfeit, err := (&bitcointree.ForfeitClosure{}).Decode(proof.Script)
				if !isForfeit || err != nil {
					continue
				}

				forfeitProof = &proof
				break
			}

			if forfeitProof == nil {
				return nil, fmt.Errorf("forfeit proof not found")
			}

			for _, connector := range connectors {
				txs, err := craftForfeitTxs(
					connector, vtxo, vtxoScript, aspScript, minRelayFee,
				)
				if err != nil {
					return nil, err
				}

				forfeitTxs = append(forfeitTxs, txs...)
			}
		}
	}
	return forfeitTxs, nil
}

func (b *txBuilder) getConnectorPkScript(poolTx string) ([]byte, error) {
	partialTx, err := psbt.NewFromRawBytes(strings.NewReader(poolTx), true)
	if err != nil {
		return nil, err
	}

	if len(partialTx.Outputs) < 1 {
		return nil, fmt.Errorf("connector output not found in pool tx")
	}

	return partialTx.UnsignedTx.TxOut[0].PkScript, nil
}
