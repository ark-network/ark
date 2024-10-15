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
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

type txBuilder struct {
	wallet            ports.WalletService
	net               common.Network
	roundLifetime     int64 // in seconds
	boardingExitDelay int64 // in seconds
}

func NewTxBuilder(
	wallet ports.WalletService, net common.Network, roundLifetime, boardingExitDelay int64,
) ports.TxBuilder {
	return &txBuilder{wallet, net, roundLifetime, boardingExitDelay}
}

func (b *txBuilder) GetTxID(tx string) (string, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", err
	}

	return ptx.UnsignedTx.TxHash().String(), nil
}

func (b *txBuilder) VerifyTapscriptPartialSigs(tx string) (bool, string, error) {
	ptx, _ := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	txid := ptx.UnsignedTx.TxID()

	for index, input := range ptx.Inputs {
		if len(input.TaprootLeafScript) == 0 {
			continue
		}

		if input.WitnessUtxo == nil {
			return false, txid, fmt.Errorf("missing witness utxo for input %d, cannot verify signature", index)
		}

		// verify taproot leaf script
		tapLeaf := input.TaprootLeafScript[0]
		if len(tapLeaf.ControlBlock) == 0 {
			return false, txid, fmt.Errorf("missing control block for input %d", index)
		}

		controlBlock, err := txscript.ParseControlBlock(tapLeaf.ControlBlock)
		if err != nil {
			return false, txid, err
		}

		rootHash := controlBlock.RootHash(tapLeaf.Script)
		tapKeyFromControlBlock := txscript.ComputeTaprootOutputKey(bitcointree.UnspendableKey(), rootHash[:])
		pkscript, err := common.P2TRScript(tapKeyFromControlBlock)
		if err != nil {
			return false, txid, err
		}

		if !bytes.Equal(pkscript, input.WitnessUtxo.PkScript) {
			return false, txid, fmt.Errorf("invalid control block for input %d", index)
		}

		preimage, err := b.getTaprootPreimage(
			tx,
			index,
			tapLeaf.Script,
		)
		if err != nil {
			return false, txid, err
		}

		for _, tapScriptSig := range input.TaprootScriptSpendSig {
			sig, err := schnorr.ParseSignature(tapScriptSig.Signature)
			if err != nil {
				return false, txid, err
			}

			pubkey, err := schnorr.ParsePubKey(tapScriptSig.XOnlyPubKey)
			if err != nil {
				return false, txid, err
			}

			if !sig.Verify(preimage, pubkey) {
				return false, txid, fmt.Errorf("invalid signature for tx %s", txid)
			}
		}
	}

	return true, txid, nil
}

func (b *txBuilder) FinalizeAndExtract(tx string) (string, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", err
	}

	for i, in := range ptx.Inputs {
		isTaproot := txscript.IsPayToTaproot(in.WitnessUtxo.PkScript)
		if isTaproot && len(in.TaprootLeafScript) > 0 {
			closure, err := bitcointree.DecodeClosure(in.TaprootLeafScript[0].Script)
			if err != nil {
				return "", err
			}

			witness := make(wire.TxWitness, 4)

			castClosure, isTaprootMultisig := closure.(*bitcointree.MultisigClosure)
			if isTaprootMultisig {
				ownerPubkey := schnorr.SerializePubKey(castClosure.Pubkey)
				aspKey := schnorr.SerializePubKey(castClosure.AspPubkey)

				for _, sig := range in.TaprootScriptSpendSig {
					if bytes.Equal(sig.XOnlyPubKey, ownerPubkey) {
						witness[0] = sig.Signature
					}

					if bytes.Equal(sig.XOnlyPubKey, aspKey) {
						witness[1] = sig.Signature
					}
				}

				witness[2] = in.TaprootLeafScript[0].Script
				witness[3] = in.TaprootLeafScript[0].ControlBlock

				for idw, w := range witness {
					if w == nil {
						return "", fmt.Errorf("missing witness element %d, cannot finalize taproot mutlisig input %d", idw, i)
					}
				}

				var witnessBuf bytes.Buffer

				if err := psbt.WriteTxWitness(&witnessBuf, witness); err != nil {
					return "", err
				}

				ptx.Inputs[i].FinalScriptWitness = witnessBuf.Bytes()
				continue
			}

		}

		if err := psbt.Finalize(ptx, i); err != nil {
			return "", fmt.Errorf("failed to finalize input %d: %w", i, err)
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
	poolTx string, payments []domain.Payment, minRelayFeeRate chainfee.SatPerKVByte,
) (connectors []string, forfeitTxs []string, err error) {
	connectorPkScript, err := b.getConnectorPkScript(poolTx)
	if err != nil {
		return nil, nil, err
	}

	minRelayFeeConnectorTx, err := b.minRelayFeeConnectorTx()
	if err != nil {
		return nil, nil, err
	}

	connectorTxs, err := b.createConnectors(poolTx, payments, connectorPkScript, minRelayFeeConnectorTx)
	if err != nil {
		return nil, nil, err
	}

	forfeitTxs, err = b.createForfeitTxs(payments, connectorTxs, minRelayFeeRate)
	if err != nil {
		return nil, nil, err
	}

	for _, tx := range connectorTxs {
		buf, _ := tx.B64Encode()
		connectors = append(connectors, buf)
	}
	return connectors, forfeitTxs, nil
}

func (b *txBuilder) BuildRoundTx(
	aspPubkey *secp256k1.PublicKey,
	payments []domain.Payment,
	boardingInputs []ports.BoardingInput,
	sweptRounds []domain.Round,
	cosigners ...*secp256k1.PublicKey,
) (roundTx string, congestionTree tree.CongestionTree, connectorAddress string, err error) {
	var sharedOutputScript []byte
	var sharedOutputAmount int64

	if len(cosigners) == 0 {
		return "", nil, "", fmt.Errorf("missing cosigners")
	}

	receivers, err := getOffchainReceivers(payments)
	if err != nil {
		return "", nil, "", err
	}

	feeAmount, err := b.minRelayFeeTreeTx()
	if err != nil {
		return "", nil, "", err
	}

	if !isOnchainOnly(payments) {
		sharedOutputScript, sharedOutputAmount, err = bitcointree.CraftSharedOutput(
			cosigners, aspPubkey, receivers, feeAmount, b.roundLifetime,
		)
		if err != nil {
			return
		}
	}

	connectorAddress, err = b.wallet.DeriveConnectorAddress(context.Background())
	if err != nil {
		return
	}

	ptx, err := b.createRoundTx(
		sharedOutputAmount, sharedOutputScript, payments, boardingInputs, connectorAddress, sweptRounds,
	)
	if err != nil {
		return
	}

	roundTx, err = ptx.B64Encode()
	if err != nil {
		return
	}

	if !isOnchainOnly(payments) {
		initialOutpoint := &wire.OutPoint{
			Hash:  ptx.UnsignedTx.TxHash(),
			Index: 0,
		}

		congestionTree, err = bitcointree.CraftCongestionTree(
			initialOutpoint, cosigners, aspPubkey, receivers, feeAmount, b.roundLifetime,
		)
		if err != nil {
			return
		}
	}

	return
}

func (b *txBuilder) GetSweepInput(node tree.Node) (lifetime int64, sweepInput ports.SweepInput, err error) {
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

	txhex, err := b.wallet.GetTransaction(context.Background(), txid.String())
	if err != nil {
		return -1, nil, err
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txhex))); err != nil {
		return -1, nil, err
	}

	sweepInput = &sweepBitcoinInput{
		inputArgs: wire.OutPoint{
			Hash:  txid,
			Index: index,
		},
		internalPubkey: internalKey,
		sweepLeaf:      sweepLeaf,
		amount:         tx.TxOut[index].Value,
	}

	return lifetime, sweepInput, nil
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

func (b *txBuilder) BuildAsyncPaymentTransactions(
	vtxos []domain.Vtxo, aspPubKey *secp256k1.PublicKey, receivers []domain.Receiver,
) (string, error) {
	if len(vtxos) <= 0 {
		return "", fmt.Errorf("missing vtxos")
	}

	ins := make([]*wire.OutPoint, 0, len(vtxos))
	outs := make([]*wire.TxOut, 0, len(receivers))
	witnessUtxos := make(map[int]*wire.TxOut)
	tapscripts := make(map[int]*psbt.TaprootTapLeafScript)

	redeemTxWeightEstimator := &input.TxWeightEstimator{}
	for index, vtxo := range vtxos {
		if vtxo.Spent || vtxo.Redeemed || vtxo.Swept {
			return "", fmt.Errorf("all vtxos must be unspent")
		}

		vtxoTxID, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return "", err
		}

		vtxoOutpoint := &wire.OutPoint{
			Hash:  *vtxoTxID,
			Index: vtxo.VOut,
		}

		vtxoScript, err := bitcointree.ParseVtxoScript(vtxo.Descriptor)
		if err != nil {
			return "", err
		}

		vtxoTapKey, vtxoTree, err := vtxoScript.TapTree()
		if err != nil {
			return "", err
		}

		vtxoOutputScript, err := common.P2TRScript(vtxoTapKey)
		if err != nil {
			return "", err
		}

		witnessUtxos[index] = &wire.TxOut{
			Value:    int64(vtxo.Amount),
			PkScript: vtxoOutputScript,
		}

		if defaultVtxoScript, ok := vtxoScript.(*bitcointree.DefaultVtxoScript); ok {
			forfeitLeaf := bitcointree.MultisigClosure{
				Pubkey:    defaultVtxoScript.Owner,
				AspPubkey: defaultVtxoScript.Asp,
			}

			tapLeaf, err := forfeitLeaf.Leaf()
			if err != nil {
				return "", err
			}

			leafProof, err := vtxoTree.GetTaprootMerkleProof(tapLeaf.TapHash())
			if err != nil {
				return "", err
			}

			tapscripts[index] = &psbt.TaprootTapLeafScript{
				ControlBlock: leafProof.ControlBlock,
				Script:       leafProof.Script,
				LeafVersion:  txscript.BaseLeafVersion,
			}

			ctrlBlock, err := txscript.ParseControlBlock(leafProof.ControlBlock)
			if err != nil {
				return "", err
			}

			redeemTxWeightEstimator.AddTapscriptInput(64*2, &waddrmgr.Tapscript{
				RevealedScript: leafProof.Script,
				ControlBlock:   ctrlBlock,
			})
		} else {
			return "", fmt.Errorf("vtxo %s:%d script is not default script, can't be async spent", vtxo.Txid, vtxo.VOut)
		}

		ins = append(ins, vtxoOutpoint)
	}

	for range receivers {
		redeemTxWeightEstimator.AddP2TROutput()
	}

	redeemTxMinRelayFee, err := b.wallet.MinRelayFee(context.Background(), uint64(redeemTxWeightEstimator.VSize()))
	if err != nil {
		return "", err
	}

	if redeemTxMinRelayFee >= receivers[len(receivers)-1].Amount {
		return "", fmt.Errorf("redeem tx fee is higher than the amount of the change receiver")
	}

	for i, receiver := range receivers {
		offchainScript, err := bitcointree.ParseVtxoScript(receiver.Descriptor)
		if err != nil {
			return "", err
		}

		receiverVtxoTaprootKey, _, err := offchainScript.TapTree()
		if err != nil {
			return "", err
		}

		newVtxoScript, err := common.P2TRScript(receiverVtxoTaprootKey)
		if err != nil {
			return "", err
		}

		// Deduct the min relay fee from the very last receiver which is supposed
		// to be the change in case it's not a send-all.
		value := receiver.Amount
		if i == len(receivers)-1 {
			value -= redeemTxMinRelayFee
		}
		outs = append(outs, &wire.TxOut{
			Value:    int64(value),
			PkScript: newVtxoScript,
		})
	}

	sequences := make([]uint32, len(ins))
	for i := range sequences {
		sequences[i] = wire.MaxTxInSequenceNum
	}

	redeemPtx, err := psbt.New(
		ins, outs, 2, 0, sequences,
	)
	if err != nil {
		return "", err
	}

	for i := range redeemPtx.Inputs {
		redeemPtx.Inputs[i].WitnessUtxo = witnessUtxos[i]
		redeemPtx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapscripts[i]}
	}

	redeemTx, err := redeemPtx.B64Encode()
	if err != nil {
		return "", err
	}

	signedRedeemTx, err := b.wallet.SignTransactionTapscript(
		context.Background(), redeemTx, nil,
	)
	if err != nil {
		return "", err
	}

	return signedRedeemTx, nil
}

// TODO use lnd CoinSelect to craft the pool tx
func (b *txBuilder) createRoundTx(
	sharedOutputAmount int64,
	sharedOutputScript []byte,
	payments []domain.Payment,
	boardingInputs []ports.BoardingInput,
	connectorAddress string,
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

	connectorMinRelayFee, err := b.minRelayFeeConnectorTx()
	if err != nil {
		return nil, err
	}

	dustLimit, err := b.wallet.GetDustAmount(context.Background())
	if err != nil {
		return nil, err
	}

	connectorAmount := dustLimit

	receivers := getOnchainReceivers(payments)
	nbOfInputs := countSpentVtxos(payments)
	connectorsAmount := (connectorAmount + connectorMinRelayFee) * nbOfInputs
	if nbOfInputs > 1 {
		connectorsAmount -= connectorMinRelayFee
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

	if connectorsAmount > 0 {
		outputs = append(outputs, &wire.TxOut{
			Value:    int64(connectorsAmount),
			PkScript: connectorScript,
		})
	}

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

	for _, input := range boardingInputs {
		targetAmount -= input.Amount
	}

	ctx := context.Background()
	utxos, change, err := b.selectUtxos(ctx, sweptRounds, targetAmount)
	if err != nil {
		return nil, err
	}

	var cacheChangeScript []byte
	// avoid derivation of several change addresses
	getChange := func() ([]byte, error) {
		if len(cacheChangeScript) > 0 {
			return cacheChangeScript, nil
		}

		changeAddresses, err := b.wallet.DeriveAddresses(ctx, 1)
		if err != nil {
			return nil, err
		}

		changeAddress, err := btcutil.DecodeAddress(changeAddresses[0], b.onchainNetwork())
		if err != nil {
			return nil, err
		}

		return txscript.PayToAddrScript(changeAddress)
	}

	exceedingValue := uint64(0)
	if change > 0 {
		if change <= dustLimit {
			exceedingValue = change
			change = 0
		} else {
			changeScript, err := getChange()
			if err != nil {
				return nil, err
			}

			outputs = append(outputs, &wire.TxOut{
				Value:    int64(change),
				PkScript: changeScript,
			})
		}
	}

	ins := make([]*wire.OutPoint, 0)
	nSequences := make([]uint32, 0)
	witnessUtxos := make(map[int]*wire.TxOut)
	tapLeaves := make(map[int]*psbt.TaprootTapLeafScript)
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

	for _, boardingInput := range boardingInputs {
		txHash, err := chainhash.NewHashFromStr(boardingInput.Txid)
		if err != nil {
			return nil, err
		}

		ins = append(ins, &wire.OutPoint{
			Hash:  *txHash,
			Index: boardingInput.VtxoKey.VOut,
		})
		nSequences = append(nSequences, wire.MaxTxInSequenceNum)

		boardingVtxoScript, err := bitcointree.ParseVtxoScript(boardingInput.Descriptor)
		if err != nil {
			return nil, err
		}

		boardingTapKey, boardingTapTree, err := boardingVtxoScript.TapTree()
		if err != nil {
			return nil, err
		}

		boardingOutputScript, err := common.P2TRScript(boardingTapKey)
		if err != nil {
			return nil, err
		}

		witnessUtxos[nextIndex] = &wire.TxOut{
			Value:    int64(boardingInput.Amount),
			PkScript: boardingOutputScript,
		}

		biggestProof, err := common.BiggestLeafMerkleProof(boardingTapTree)
		if err != nil {
			return nil, err
		}

		tapLeaves[nextIndex] = &psbt.TaprootTapLeafScript{
			Script:       biggestProof.Script,
			ControlBlock: biggestProof.ControlBlock,
		}

		nextIndex++
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

	for inIndex, tapLeaf := range tapLeaves {
		updater.Upsbt.Inputs[inIndex].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapLeaf}
	}

	b64, err := ptx.B64Encode()
	if err != nil {
		return nil, err
	}

	feeAmount, err := b.wallet.EstimateFees(ctx, b64)
	if err != nil {
		return nil, err
	}

	for feeAmount > exceedingValue {
		feesToPay := feeAmount - exceedingValue

		// change is able to cover the remaining fees
		if change > feesToPay {
			newChange := change - (feeAmount - exceedingValue)
			// new change amount is less than dust limit, let's remove it
			if newChange <= dustLimit {
				ptx.UnsignedTx.TxOut = ptx.UnsignedTx.TxOut[:len(ptx.UnsignedTx.TxOut)-1]
				ptx.Outputs = ptx.Outputs[:len(ptx.Outputs)-1]
			} else {
				ptx.UnsignedTx.TxOut[len(ptx.Outputs)-1].Value = int64(newChange)
			}

			break
		}

		// change is not enough to cover the remaining fees, let's re-select utxos
		newUtxos, newChange, err := b.wallet.SelectUtxos(ctx, "", feeAmount-exceedingValue)
		if err != nil {
			return nil, err
		}

		// add new inputs
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

		// add new change output if necessary
		if newChange > 0 {
			if newChange <= dustLimit {
				newChange = 0
				exceedingValue += newChange
			} else {
				changeScript, err := getChange()
				if err != nil {
					return nil, err
				}

				ptx.UnsignedTx.AddTxOut(&wire.TxOut{
					Value:    int64(newChange),
					PkScript: changeScript,
				})
				ptx.Outputs = append(ptx.Outputs, psbt.POutput{})
			}
		}

		b64, err = ptx.B64Encode()
		if err != nil {
			return nil, err
		}

		newFeeAmount, err := b.wallet.EstimateFees(ctx, b64)
		if err != nil {
			return nil, err
		}

		feeAmount = newFeeAmount
		change = newChange
	}

	// remove input taproot leaf script
	// used only to compute an accurate fee estimation
	for i := range ptx.Inputs {
		ptx.Inputs[i].TaprootLeafScript = nil
	}

	return ptx, nil
}

func (b *txBuilder) minRelayFeeConnectorTx() (uint64, error) {
	return b.wallet.MinRelayFee(context.Background(), uint64(common.ConnectorTxSize))
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
			roundTx.Inputs[i].TaprootLeafScript = sourceInput.TaprootLeafScript
		}
	}

	return roundTx.B64Encode()
}

func (b *txBuilder) createConnectors(
	poolTx string, payments []domain.Payment, connectorScript []byte, feeAmount uint64,
) ([]*psbt.Packet, error) {
	partialTx, err := psbt.NewFromRawBytes(strings.NewReader(poolTx), true)
	if err != nil {
		return nil, err
	}

	connectorAmount, err := b.wallet.GetDustAmount(context.Background())
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
		connectorTx, err := craftConnectorTx(previousInput, connectorScript, outputs, feeAmount)
		if err != nil {
			return nil, err
		}

		return []*psbt.Packet{connectorTx}, nil
	}

	totalConnectorAmount := (connectorAmount + feeAmount) * numberOfConnectors
	if numberOfConnectors > 1 {
		totalConnectorAmount -= feeAmount
	}

	connectors := make([]*psbt.Packet, 0, numberOfConnectors-1)
	for i := uint64(0); i < numberOfConnectors-1; i++ {
		outputs := []*wire.TxOut{connectorOutput}
		totalConnectorAmount -= connectorAmount
		totalConnectorAmount -= feeAmount
		if totalConnectorAmount > 0 {
			outputs = append(outputs, &wire.TxOut{
				PkScript: connectorScript,
				Value:    int64(totalConnectorAmount),
			})
		}
		connectorTx, err := craftConnectorTx(previousInput, connectorScript, outputs, feeAmount)
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

func (b *txBuilder) minRelayFeeTreeTx() (uint64, error) {
	return b.wallet.MinRelayFee(context.Background(), uint64(common.TreeTxSize))
}

func (b *txBuilder) createForfeitTxs(
	payments []domain.Payment,
	connectors []*psbt.Packet,
	minRelayFeeRate chainfee.SatPerKVByte,
) ([]string, error) {
	forfeitAddress, err := b.wallet.GetForfeitAddress(context.Background())
	if err != nil {
		return nil, err
	}

	parsedAddr, err := btcutil.DecodeAddress(forfeitAddress, b.onchainNetwork())
	if err != nil {
		return nil, err
	}

	pkScript, err := txscript.PayToAddrScript(parsedAddr)
	if err != nil {
		return nil, err
	}

	scriptParsed, err := txscript.ParsePkScript(pkScript)
	if err != nil {
		return nil, err
	}

	forfeitTxs := make([]string, 0)
	for _, payment := range payments {
		for _, vtxo := range payment.Inputs {
			offchainscript, err := bitcointree.ParseVtxoScript(vtxo.Descriptor)
			if err != nil {
				return nil, err
			}

			vtxoTaprootKey, tapTree, err := offchainscript.TapTree()
			if err != nil {
				return nil, err
			}

			connectorAmount, err := b.wallet.GetDustAmount(context.Background())
			if err != nil {
				return nil, err
			}

			vtxoScript, err := common.P2TRScript(vtxoTaprootKey)
			if err != nil {
				return nil, err
			}

			feeAmount, err := common.ComputeForfeitMinRelayFee(minRelayFeeRate, tapTree, scriptParsed.Class())
			if err != nil {
				return nil, err
			}

			vtxoTxHash, err := chainhash.NewHashFromStr(vtxo.Txid)
			if err != nil {
				return nil, err
			}

			for _, connector := range connectors {
				txs, err := bitcointree.BuildForfeitTxs(
					connector,
					&wire.OutPoint{
						Hash:  *vtxoTxHash,
						Index: vtxo.VOut,
					},
					vtxo.Amount,
					connectorAmount,
					feeAmount,
					vtxoScript,
					pkScript,
				)
				if err != nil {
					return nil, err
				}

				for _, tx := range txs {
					b64, err := tx.B64Encode()
					if err != nil {
						return nil, err
					}
					forfeitTxs = append(forfeitTxs, b64)
				}

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

	return partialTx.UnsignedTx.TxOut[1].PkScript, nil
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

		fmt.Println("closure", valid)
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
