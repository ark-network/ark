package txbuilder

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
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
	wallet                   ports.WalletService
	net                      common.Network
	roundLifetime            int64 // in seconds
	exitDelay                int64 // in seconds
	reverseBoardingExitDelay int64 // in seconds
}

func NewTxBuilder(
	wallet ports.WalletService, net common.Network, roundLifetime, exitDelay, reverseBoardingExitDelay int64,
) ports.TxBuilder {
	return &txBuilder{wallet, net, roundLifetime, exitDelay, reverseBoardingExitDelay}
}

func (b *txBuilder) VerifyForfeitTx(tx string) (bool, string, error) {
	ptx, _ := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	txid := ptx.UnsignedTx.TxHash().String()

	for index, input := range ptx.Inputs {
		// TODO (@louisinger): verify control block
		for _, tapScriptSig := range input.TaprootScriptSpendSig {
			preimage, err := b.getTaprootPreimage(
				tx,
				index,
				input.TaprootLeafScript[0].Script,
			)
			if err != nil {
				return false, txid, err
			}

			sig, err := schnorr.ParseSignature(tapScriptSig.Signature)
			if err != nil {
				return false, txid, err
			}

			pubkey, err := schnorr.ParsePubKey(tapScriptSig.XOnlyPubKey)
			if err != nil {
				return false, txid, err
			}

			if sig.Verify(preimage, pubkey) {
				return true, txid, nil
			} else {
				return false, txid, fmt.Errorf("invalid signature for tx %s", txid)
			}
		}
	}

	return false, txid, nil
}

func (b *txBuilder) FinalizeAndExtractForfeit(tx string) (string, error) {
	ptx, _ := psbt.NewFromRawBytes(strings.NewReader(tx), true)

	for i := range ptx.Inputs {
		if err := psbt.Finalize(ptx, i); err != nil {
			return "", err
		}
	}

	signed, err := psbt.Extract(ptx)
	if err != nil {
		return "", err
	}

	var serialized bytes.Buffer

	if err := signed.Serialize(&serialized); err != nil {
		return "", err
	}

	return hex.EncodeToString(serialized.Bytes()), nil
}

func (b *txBuilder) GetVtxoScript(userPubkey, aspPubkey *secp256k1.PublicKey) ([]byte, error) {
	outputScript, _, err := b.getLeafScriptAndTree(userPubkey, aspPubkey)
	if err != nil {
		return nil, err
	}
	return outputScript, nil
}

func (b *txBuilder) BuildSweepTx(inputs []ports.SweepInput) (signedSweepTx string, err error) {
	sweepPsbt, err := sweepTransaction(
		b.wallet,
		inputs,
	)
	if err != nil {
		return "", err
	}

	sweepPsbtBase64, err := sweepPsbt.B64Encode()
	if err != nil {
		return "", err
	}

	ctx := context.Background()
	signedSweepPsbtB64, err := b.wallet.SignTransactionTapscript(ctx, sweepPsbtBase64, nil)
	if err != nil {
		return "", err
	}

	signedPsbt, err := psbt.NewFromRawBytes(strings.NewReader(signedSweepPsbtB64), true)
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
	aspPubkey *secp256k1.PublicKey, payments []domain.Payment, minRelayFee uint64, sweptRounds []domain.Round, cosigners ...*secp256k1.PublicKey,
) (poolTx string, congestionTree tree.CongestionTree, connectorAddress string, err error) {
	var sharedOutputScript []byte
	var sharedOutputAmount int64

	if len(cosigners) == 0 {
		return "", nil, "", fmt.Errorf("missing cosigners")
	}

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
		aspPubkey, sharedOutputAmount, sharedOutputScript, payments, connectorAddress, minRelayFee, sweptRounds,
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

func (b *txBuilder) GetSweepInput(parentblocktime int64, node tree.Node) (expirationtime int64, sweepInput ports.SweepInput, err error) {
	partialTx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
	if err != nil {
		return -1, nil, err
	}

	if len(partialTx.Inputs) != 1 {
		return -1, nil, fmt.Errorf("invalid node pset, expect 1 input, got %d", len(partialTx.Inputs))
	}

	input := partialTx.UnsignedTx.TxIn[0]
	txid := input.PreviousOutPoint.Hash
	index := input.PreviousOutPoint.Index

	sweepLeaf, internalKey, lifetime, err := extractSweepLeaf(partialTx.Inputs[0])
	if err != nil {
		return -1, nil, err
	}

	expirationTime := parentblocktime + lifetime

	amount := int64(0)
	for _, out := range partialTx.UnsignedTx.TxOut {
		amount += out.Value
	}

	sweepInput = &sweepBitcoinInput{
		inputArgs: wire.OutPoint{
			Hash:  txid,
			Index: index,
		},
		internalPubkey: internalKey,
		sweepLeaf:      sweepLeaf,
		amount:         amount,
	}

	return expirationTime, sweepInput, nil
}

func (b *txBuilder) FindLeaves(congestionTree tree.CongestionTree, fromtxid string, vout uint32) ([]tree.Node, error) {
	allLeaves := congestionTree.Leaves()
	foundLeaves := make([]tree.Node, 0)

	for _, leaf := range allLeaves {
		branch, err := congestionTree.Branch(leaf.Txid)
		if err != nil {
			return nil, err
		}

		for _, node := range branch {
			ptx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
			if err != nil {
				return nil, err
			}

			if len(ptx.Inputs) <= 0 {
				return nil, fmt.Errorf("no input in the pset")
			}

			parentInput := ptx.UnsignedTx.TxIn[0].PreviousOutPoint

			if parentInput.Hash.String() == fromtxid && parentInput.Index == vout {
				foundLeaves = append(foundLeaves, leaf)
				break
			}
		}
	}

	return foundLeaves, nil
}

// TODO add locktimes to txs
func (b *txBuilder) BuildAsyncPaymentTransactions(
	vtxos []domain.Vtxo, aspPubKey *secp256k1.PublicKey,
	receivers []domain.Receiver, minRelayFee uint64,
) (*domain.AsyncPaymentTxs, error) {
	if len(vtxos) <= 0 {
		return nil, fmt.Errorf("missing vtxos")
	}

	ins := make([]*wire.OutPoint, 0, len(vtxos))
	outs := make([]*wire.TxOut, 0, len(receivers))
	unconditionalForfeitTxs := make([]string, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if vtxo.Spent {
			return nil, fmt.Errorf("all vtxos must be unspent")
		}

		senderBytes, err := hex.DecodeString(vtxo.Pubkey)
		if err != nil {
			return nil, err
		}

		sender, err := secp256k1.ParsePubKey(senderBytes)
		if err != nil {
			return nil, err
		}

		aspScript, err := p2trScript(aspPubKey, b.onchainNetwork())
		if err != nil {
			return nil, err
		}

		vtxoTxID, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return nil, err
		}

		vtxoOutpoint := &wire.OutPoint{
			Hash:  *vtxoTxID,
			Index: vtxo.VOut,
		}

		vtxoScript, vtxoTree, err := b.getLeafScriptAndTree(sender, aspPubKey)
		if err != nil {
			return nil, err
		}

		output := &wire.TxOut{
			PkScript: aspScript,
			Value:    int64(vtxo.Amount - minRelayFee),
		}

		forfeitClosure := &bitcointree.MultisigClosure{
			Pubkey:    sender,
			AspPubkey: aspPubKey,
		}

		forfeitLeaf, err := forfeitClosure.Leaf()
		if err != nil {
			return nil, err
		}

		leafProof := vtxoTree.LeafMerkleProofs[vtxoTree.LeafProofIndex[forfeitLeaf.TapHash()]]
		ctrlBlock := leafProof.ToControlBlock(bitcointree.UnspendableKey())
		ctrlBlockBytes, err := ctrlBlock.ToBytes()
		if err != nil {
			return nil, err
		}

		unconditionnalForfeitPtx, err := psbt.New(
			[]*wire.OutPoint{vtxoOutpoint},
			[]*wire.TxOut{output},
			2,
			0,
			[]uint32{wire.MaxTxInSequenceNum},
		)
		if err != nil {
			return nil, err
		}

		unconditionnalForfeitPtx.Inputs[0].WitnessUtxo = &wire.TxOut{
			Value:    int64(vtxo.Amount),
			PkScript: vtxoScript,
		}

		unconditionnalForfeitPtx.Inputs[0].TaprootInternalKey = schnorr.SerializePubKey(bitcointree.UnspendableKey())
		unconditionnalForfeitPtx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
			{
				ControlBlock: ctrlBlockBytes,
				Script:       forfeitLeaf.Script,
				LeafVersion:  txscript.BaseLeafVersion,
			},
		}

		forfeitTx, err := unconditionnalForfeitPtx.B64Encode()
		if err != nil {
			return nil, err
		}

		unconditionalForfeitTxs = append(unconditionalForfeitTxs, forfeitTx)
		ins = append(ins, vtxoOutpoint)
	}

	for i, receiver := range receivers {
		// TODO (@louisinger): Add revert policy (sender+ASP)
		buf, err := hex.DecodeString(receiver.Pubkey)
		if err != nil {
			return nil, err
		}
		receiverPk, err := secp256k1.ParsePubKey(buf)
		if err != nil {
			return nil, err
		}
		newVtxoScript, _, err := b.getLeafScriptAndTree(receiverPk, aspPubKey)
		if err != nil {
			return nil, err
		}

		// Deduct the min relay fee from the very last receiver which is supposed
		// to be the change in case it's not a send-all.
		value := receiver.Amount
		if i == len(receivers)-1 {
			value -= minRelayFee
		}
		outs = append(outs, &wire.TxOut{
			Value:    int64(value),
			PkScript: newVtxoScript,
		})
	}

	redeemPtx, err := psbt.New(
		ins, outs, 2, 0, []uint32{wire.MaxTxInSequenceNum},
	)
	if err != nil {
		return nil, err
	}

	for i := range redeemPtx.Inputs {
		unconditionnalForfeitPsbt, _ := psbt.NewFromRawBytes(
			strings.NewReader(unconditionalForfeitTxs[i]), true,
		)
		redeemPtx.Inputs[i].WitnessUtxo = unconditionnalForfeitPsbt.Inputs[0].WitnessUtxo
		redeemPtx.Inputs[i].TaprootInternalKey = unconditionnalForfeitPsbt.Inputs[0].TaprootInternalKey
		redeemPtx.Inputs[i].TaprootLeafScript = unconditionnalForfeitPsbt.Inputs[0].TaprootLeafScript

	}

	redeemTx, err := redeemPtx.B64Encode()
	if err != nil {
		return nil, err
	}

	signedRedeemTx, err := b.wallet.SignTransactionTapscript(
		context.Background(), redeemTx, nil,
	)
	if err != nil {
		return nil, err
	}

	return &domain.AsyncPaymentTxs{
		RedeemTx:                signedRedeemTx,
		UnconditionalForfeitTxs: unconditionalForfeitTxs,
	}, nil
}

func (b *txBuilder) GetReverseBoardingScript(userPubkey, aspPubkey *secp256k1.PublicKey) (string, []byte, error) {
	addr, script, _, err := b.craftReverseBoardingTaproot(userPubkey, aspPubkey)
	if err != nil {
		return "", nil, err
	}

	return addr, script, nil
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

	forfeitClosure := &bitcointree.MultisigClosure{
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
	unspendableKey := bitcointree.UnspendableKey()
	taprootKey := txscript.ComputeTaprootOutputKey(unspendableKey, root[:])

	outputScript, err := taprootOutputScript(taprootKey)
	if err != nil {
		return nil, nil, err
	}

	return outputScript, taprootTree, nil
}

func (b *txBuilder) createPoolTx(
	aspPubKey *secp256k1.PublicKey,
	sharedOutputAmount int64, sharedOutputScript []byte,
	payments []domain.Payment, connectorAddress string, minRelayFee uint64,
	sweptRounds []domain.Round,
) (*psbt.Packet, error) {
	connectorAddr, err := btcutil.DecodeAddress(connectorAddress, b.onchainNetwork())
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

		receiverAddr, err := btcutil.DecodeAddress(receiver.OnchainAddress, b.onchainNetwork())
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

	for _, payment := range payments {
		for _, reverseBoarding := range payment.ReverseBoardingInputs {
			targetAmount -= uint64(reverseBoarding.Value)
		}
	}

	ctx := context.Background()
	utxos, change, err := b.selectUtxos(ctx, sweptRounds, targetAmount)
	if err != nil {
		return nil, err
	}

	var dust uint64
	if change > 0 {
		if change < dustLimit {
			dust = change
			change = 0
		} else {
			address, err := b.wallet.DeriveAddresses(ctx, 1)
			if err != nil {
				return nil, err
			}

			addr, err := btcutil.DecodeAddress(address[0], b.onchainNetwork())
			if err != nil {
				return nil, err
			}

			aspScript, err := txscript.PayToAddrScript(addr)
			if err != nil {
				return nil, err
			}

			outputs = append(outputs, &wire.TxOut{
				Value:    int64(change),
				PkScript: aspScript,
			})
		}
	}

	ins := make([]*wire.OutPoint, 0)
	nSequences := make([]uint32, 0)
	witnessUtxos := make(map[int]*wire.TxOut)
	reverseBoardingTapLeaf := make(map[int]*psbt.TaprootTapLeafScript)
	nextIndex := 0

	for _, utxo := range utxos {
		txhash, err := chainhash.NewHashFromStr(utxo.GetTxid())
		if err != nil {
			return nil, err
		}

		ins = append(ins, &wire.OutPoint{
			Hash:  *txhash,
			Index: utxo.GetIndex(),
		})
		nSequences = append(nSequences, wire.MaxTxInSequenceNum)

		script, err := hex.DecodeString(utxo.GetScript())
		if err != nil {
			return nil, err
		}

		witnessUtxos[nextIndex] = &wire.TxOut{
			Value:    int64(utxo.GetValue()),
			PkScript: script,
		}
		nextIndex++
	}

	for _, payment := range payments {
		for _, reverseBoarding := range payment.ReverseBoardingInputs {
			txhash, err := chainhash.NewHashFromStr(reverseBoarding.Txid)
			if err != nil {
				return nil, err
			}

			ins = append(ins, &wire.OutPoint{
				Hash:  *txhash,
				Index: reverseBoarding.VOut,
			})
			nSequences = append(nSequences, wire.MaxTxInSequenceNum)

			userPubkeyBytes, err := hex.DecodeString(reverseBoarding.OwnerPublicKey)
			if err != nil {
				return nil, err
			}

			userPubkey, err := secp256k1.ParsePubKey(userPubkeyBytes)
			if err != nil {
				return nil, err
			}

			_, script, tapLeaf, err := b.craftReverseBoardingTaproot(userPubkey, aspPubKey)
			if err != nil {
				return nil, err
			}

			reverseBoardingTapLeaf[nextIndex] = tapLeaf
			witnessUtxos[nextIndex] = &wire.TxOut{
				Value:    int64(reverseBoarding.Value),
				PkScript: script,
			}
			nextIndex++
		}
	}

	ptx, err := psbt.New(ins, outputs, 2, 0, nSequences)
	if err != nil {
		return nil, err
	}

	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return nil, err
	}

	for inIndex, utxo := range witnessUtxos {
		if err := updater.AddInWitnessUtxo(utxo, inIndex); err != nil {
			return nil, err
		}
	}

	unspendableInternalKey := schnorr.SerializePubKey(bitcointree.UnspendableKey())

	for inIndex, tapLeaf := range reverseBoardingTapLeaf {
		updater.Upsbt.Inputs[inIndex].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapLeaf}
		updater.Upsbt.Inputs[inIndex].TaprootInternalKey = unspendableInternalKey
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
			newUtxos, change, err := b.selectUtxos(ctx, sweptRounds, feeAmount-change)
			if err != nil {
				return nil, err
			}

			if change > 0 {
				address, err := b.wallet.DeriveAddresses(ctx, 1)
				if err != nil {
					return nil, err
				}

				addr, err := btcutil.DecodeAddress(address[0], b.onchainNetwork())
				if err != nil {
					return nil, err
				}

				aspScript, err := txscript.PayToAddrScript(addr)
				if err != nil {
					return nil, err
				}

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
		newUtxos, change, err := b.selectUtxos(ctx, sweptRounds, feeAmount-dust)
		if err != nil {
			return nil, err
		}

		if change > 0 {
			if change > dustLimit {
				address, err := b.wallet.DeriveAddresses(ctx, 1)
				if err != nil {
					return nil, err
				}

				addr, err := btcutil.DecodeAddress(address[0], b.onchainNetwork())
				if err != nil {
					return nil, err
				}

				aspScript, err := txscript.PayToAddrScript(addr)
				if err != nil {
					return nil, err
				}

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

func (b *txBuilder) VerifyAndCombinePartialTx(dest string, src string) (string, error) {
	roundTx, err := psbt.NewFromRawBytes(strings.NewReader(dest), true)
	if err != nil {
		return "", err
	}

	sourceTx, err := psbt.NewFromRawBytes(strings.NewReader(src), true)
	if err != nil {
		return "", err
	}

	if sourceTx.UnsignedTx.TxHash().String() != roundTx.UnsignedTx.TxHash().String() {
		return "", fmt.Errorf("txids do not match")
	}

	for i, in := range sourceTx.Inputs {
		isMultisigTaproot := len(in.TaprootLeafScript) > 0
		if isMultisigTaproot {
			// check if the source tx signs the leaf
			sourceInput := sourceTx.Inputs[i]

			if len(sourceInput.TaprootScriptSpendSig) == 0 {
				continue
			}

			partialSig := sourceInput.TaprootScriptSpendSig[0]
			preimage, err := b.getTaprootPreimage(src, i, sourceInput.TaprootLeafScript[0].Script)
			if err != nil {
				return "", err
			}

			sig, err := schnorr.ParseSignature(partialSig.Signature)
			if err != nil {
				return "", err
			}

			pubkey, err := schnorr.ParsePubKey(partialSig.XOnlyPubKey)
			if err != nil {
				return "", err
			}

			if !sig.Verify(preimage, pubkey) {
				return "", fmt.Errorf(
					"invalid signature for input %s:%d",
					sourceTx.UnsignedTx.TxIn[i].PreviousOutPoint.Hash.String(),
					sourceTx.UnsignedTx.TxIn[i].PreviousOutPoint.Index,
				)
			}

			roundTx.Inputs[i].TaprootScriptSpendSig = sourceInput.TaprootScriptSpendSig
		}
	}

	return roundTx.B64Encode()
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
	// TODO (@louisinger): are we sure about this change?
	aspScript, err := p2trScript(aspPubkey, b.onchainNetwork())
	// aspScript, err := p2wpkhScript(aspPubkey, b.onchainNetwork())
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
				isForfeit, err := (&bitcointree.MultisigClosure{}).Decode(proof.Script)
				if !isForfeit || err != nil {
					continue
				}

				forfeitProof = &proof
				break
			}

			if forfeitProof == nil {
				return nil, fmt.Errorf("forfeit proof not found")
			}

			controlBlock := forfeitProof.ToControlBlock(bitcointree.UnspendableKey())
			ctrlBlockBytes, err := controlBlock.ToBytes()
			if err != nil {
				return nil, err
			}

			for _, connector := range connectors {
				txs, err := craftForfeitTxs(
					connector, vtxo,
					&psbt.TaprootTapLeafScript{
						ControlBlock: ctrlBlockBytes,
						Script:       forfeitProof.Script,
						LeafVersion:  forfeitProof.LeafVersion,
					},
					vtxoScript, aspScript, minRelayFee,
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

func (b *txBuilder) selectUtxos(ctx context.Context, sweptRounds []domain.Round, amount uint64) ([]ports.TxInput, uint64, error) {
	selectedConnectorsUtxos := make([]ports.TxInput, 0)
	selectedConnectorsAmount := uint64(0)

	for _, round := range sweptRounds {
		if selectedConnectorsAmount >= amount {
			break
		}
		connectors, err := b.wallet.ListConnectorUtxos(ctx, round.ConnectorAddress)
		if err != nil {
			return nil, 0, err
		}

		for _, connector := range connectors {
			if selectedConnectorsAmount >= amount {
				break
			}

			selectedConnectorsUtxos = append(selectedConnectorsUtxos, connector)
			selectedConnectorsAmount += connector.GetValue()
		}
	}

	if len(selectedConnectorsUtxos) > 0 {
		if err := b.wallet.LockConnectorUtxos(ctx, castToOutpoints(selectedConnectorsUtxos)); err != nil {
			return nil, 0, err
		}
	}

	if selectedConnectorsAmount >= amount {
		return selectedConnectorsUtxos, selectedConnectorsAmount - amount, nil
	}

	utxos, change, err := b.wallet.SelectUtxos(ctx, "", amount-selectedConnectorsAmount)
	if err != nil {
		return nil, 0, err
	}

	return append(selectedConnectorsUtxos, utxos...), change, nil
}

func (b *txBuilder) getTaprootPreimage(tx string, inputIndex int, leafScript []byte) ([]byte, error) {
	partial, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return nil, err
	}

	prevouts := make(map[wire.OutPoint]*wire.TxOut)

	for i, input := range partial.Inputs {
		if input.WitnessUtxo == nil {
			return nil, fmt.Errorf("missing witness utxo on input #%d", i)
		}

		outpoint := partial.UnsignedTx.TxIn[i].PreviousOutPoint
		prevouts[outpoint] = input.WitnessUtxo
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)

	return txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(partial.UnsignedTx, prevoutFetcher),
		txscript.SigHashDefault,
		partial.UnsignedTx,
		inputIndex,
		prevoutFetcher,
		txscript.NewBaseTapLeaf(leafScript),
	)
}

func (b *txBuilder) onchainNetwork() *chaincfg.Params {
	mutinyNetSigNetParams := chaincfg.CustomSignetParams(common.MutinyNetChallenge, nil)
	mutinyNetSigNetParams.TargetTimePerBlock = common.MutinyNetBlockTime
	switch b.net.Name {
	case common.Bitcoin.Name:
		return &chaincfg.MainNetParams
	case common.BitcoinTestNet.Name:
		return &chaincfg.TestNet3Params
	case common.BitcoinRegTest.Name:
		return &chaincfg.RegressionNetParams
	case common.BitcoinSigNet.Name:
		return &mutinyNetSigNetParams
	default:
		return nil
	}
}

// craftReverseBoardingTaproot returns the addr, script and the leaf belonging to the ASP
func (b *txBuilder) craftReverseBoardingTaproot(userPubkey, aspPubkey *secp256k1.PublicKey) (string, []byte, *psbt.TaprootTapLeafScript, error) {
	multisigClosure := bitcointree.MultisigClosure{
		Pubkey:    userPubkey,
		AspPubkey: aspPubkey,
	}

	csvClosure := bitcointree.CSVSigClosure{
		Pubkey:  userPubkey,
		Seconds: uint(b.reverseBoardingExitDelay),
	}

	multisigLeaf, err := multisigClosure.Leaf()
	if err != nil {
		return "", nil, nil, err
	}

	csvLeaf, err := csvClosure.Leaf()
	if err != nil {
		return "", nil, nil, err
	}

	tree := txscript.AssembleTaprootScriptTree(*multisigLeaf, *csvLeaf)

	root := tree.RootNode.TapHash()

	taprootKey := txscript.ComputeTaprootOutputKey(bitcointree.UnspendableKey(), root[:])
	script, err := txscript.PayToTaprootScript(taprootKey)
	if err != nil {
		return "", nil, nil, err
	}

	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(taprootKey), b.onchainNetwork())
	if err != nil {
		return "", nil, nil, err
	}

	proofIndex := tree.LeafProofIndex[multisigLeaf.TapHash()]
	proof := tree.LeafMerkleProofs[proofIndex]

	ctrlBlock := proof.ToControlBlock(bitcointree.UnspendableKey())
	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	if err != nil {
		return "", nil, nil, err
	}

	tapLeaf := &psbt.TaprootTapLeafScript{
		ControlBlock: ctrlBlockBytes,
		Script:       multisigLeaf.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}

	return addr.String(), script, tapLeaf, nil
}

func castToOutpoints(inputs []ports.TxInput) []ports.TxOutpoint {
	outpoints := make([]ports.TxOutpoint, 0, len(inputs))
	for _, input := range inputs {
		outpoints = append(outpoints, input)
	}
	return outpoints
}

func extractSweepLeaf(input psbt.PInput) (sweepLeaf *psbt.TaprootTapLeafScript, internalKey *secp256k1.PublicKey, lifetime int64, err error) {
	for _, leaf := range input.TaprootLeafScript {
		closure := &bitcointree.CSVSigClosure{}
		valid, err := closure.Decode(leaf.Script)
		if err != nil {
			return nil, nil, 0, err
		}
		if valid && closure.Seconds > 0 {
			sweepLeaf = leaf
			lifetime = int64(closure.Seconds)
		}
	}

	internalKey, err = schnorr.ParsePubKey(input.TaprootInternalKey)
	if err != nil {
		return nil, nil, 0, err
	}

	if sweepLeaf == nil {
		return nil, nil, 0, fmt.Errorf("sweep leaf not found")
	}

	return sweepLeaf, internalKey, lifetime, nil
}

type sweepBitcoinInput struct {
	inputArgs      wire.OutPoint
	sweepLeaf      *psbt.TaprootTapLeafScript
	internalPubkey *secp256k1.PublicKey
	amount         int64
}

func (s *sweepBitcoinInput) GetAmount() uint64 {
	return uint64(s.amount)
}

func (s *sweepBitcoinInput) GetControlBlock() []byte {
	return s.sweepLeaf.ControlBlock
}

func (s *sweepBitcoinInput) GetHash() chainhash.Hash {
	return s.inputArgs.Hash
}

func (s *sweepBitcoinInput) GetIndex() uint32 {
	return s.inputArgs.Index
}

func (s *sweepBitcoinInput) GetInternalKey() *secp256k1.PublicKey {
	return s.internalPubkey
}

func (s *sweepBitcoinInput) GetLeafScript() []byte {
	return s.sweepLeaf.Script
}
