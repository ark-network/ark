package txbuilder

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
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
)

type txBuilder struct {
	wallet            ports.WalletService
	net               common.Network
	vtxoTreeExpiry    common.RelativeLocktime
	boardingExitDelay common.RelativeLocktime
}

func NewTxBuilder(
	wallet ports.WalletService, net common.Network, vtxoTreeExpiry, boardingExitDelay common.RelativeLocktime,
) ports.TxBuilder {
	return &txBuilder{wallet, net, vtxoTreeExpiry, boardingExitDelay}
}

func (b *txBuilder) GetTxID(tx string) (string, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", err
	}

	return ptx.UnsignedTx.TxHash().String(), nil
}

func (b *txBuilder) VerifyTapscriptPartialSigs(tx string) (bool, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return false, err
	}

	return b.verifyTapscriptPartialSigs(ptx)
}

func (b *txBuilder) verifyTapscriptPartialSigs(ptx *psbt.Packet) (bool, error) {
	txid := ptx.UnsignedTx.TxID()

	serverPubkey, err := b.wallet.GetPubkey(context.Background())
	if err != nil {
		return false, err
	}

	for index, input := range ptx.Inputs {
		if len(input.TaprootLeafScript) == 0 {
			continue
		}

		if input.WitnessUtxo == nil {
			return false, fmt.Errorf("missing witness utxo for input %d, cannot verify signature", index)
		}

		// verify taproot leaf script
		tapLeaf := input.TaprootLeafScript[0]

		closure, err := tree.DecodeClosure(tapLeaf.Script)
		if err != nil {
			return false, err
		}

		keys := make(map[string]bool)

		switch c := closure.(type) {
		case *tree.MultisigClosure:
			for _, key := range c.PubKeys {
				keys[hex.EncodeToString(schnorr.SerializePubKey(key))] = false
			}
		case *tree.CSVMultisigClosure:
			for _, key := range c.PubKeys {
				keys[hex.EncodeToString(schnorr.SerializePubKey(key))] = false
			}
		case *tree.CLTVMultisigClosure:
			for _, key := range c.PubKeys {
				keys[hex.EncodeToString(schnorr.SerializePubKey(key))] = false
			}
		case *tree.ConditionMultisigClosure:
			witness, err := bitcointree.GetConditionWitness(input)
			if err != nil {
				return false, err
			}

			result, err := tree.ExecuteBoolScript(c.Condition, witness)
			if err != nil {
				return false, err
			}

			if !result {
				return false, fmt.Errorf("condition not met for input %d", index)
			}

			for _, key := range c.PubKeys {
				keys[hex.EncodeToString(schnorr.SerializePubKey(key))] = false
			}
		}

		// we don't need to check if server signed
		keys[hex.EncodeToString(schnorr.SerializePubKey(serverPubkey))] = true

		if len(tapLeaf.ControlBlock) == 0 {
			return false, fmt.Errorf("missing control block for input %d", index)
		}

		controlBlock, err := txscript.ParseControlBlock(tapLeaf.ControlBlock)
		if err != nil {
			return false, err
		}

		rootHash := controlBlock.RootHash(tapLeaf.Script)
		tapKeyFromControlBlock := txscript.ComputeTaprootOutputKey(bitcointree.UnspendableKey(), rootHash[:])
		pkscript, err := common.P2TRScript(tapKeyFromControlBlock)
		if err != nil {
			return false, err
		}

		if !bytes.Equal(pkscript, input.WitnessUtxo.PkScript) {
			return false, fmt.Errorf("invalid control block for input %d", index)
		}

		preimage, err := b.getTaprootPreimage(
			ptx,
			index,
			tapLeaf.Script,
		)
		if err != nil {
			return false, err
		}

		for _, tapScriptSig := range input.TaprootScriptSpendSig {
			sig, err := schnorr.ParseSignature(tapScriptSig.Signature)
			if err != nil {
				return false, err
			}

			pubkey, err := schnorr.ParsePubKey(tapScriptSig.XOnlyPubKey)
			if err != nil {
				return false, err
			}

			if !sig.Verify(preimage, pubkey) {
				return false, fmt.Errorf("invalid signature for tx %s", txid)
			}

			keys[hex.EncodeToString(schnorr.SerializePubKey(pubkey))] = true
		}

		missingSigs := 0
		for key := range keys {
			if !keys[key] {
				missingSigs++
			}
		}

		if missingSigs > 0 {
			return false, fmt.Errorf("missing %d signatures", missingSigs)
		}
	}

	return true, nil
}

func (b *txBuilder) FinalizeAndExtract(tx string) (string, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", err
	}

	for i, in := range ptx.Inputs {
		isTaproot := txscript.IsPayToTaproot(in.WitnessUtxo.PkScript)
		if isTaproot && len(in.TaprootLeafScript) > 0 {
			closure, err := tree.DecodeClosure(in.TaprootLeafScript[0].Script)
			if err != nil {
				return "", err
			}

			conditionWitness, err := bitcointree.GetConditionWitness(in)
			if err != nil {
				return "", err
			}

			args := make(map[string][]byte)
			if len(conditionWitness) > 0 {
				var conditionWitnessBytes bytes.Buffer
				if err := psbt.WriteTxWitness(&conditionWitnessBytes, conditionWitness); err != nil {
					return "", err
				}
				args[tree.ConditionWitnessKey] = conditionWitnessBytes.Bytes()
			}

			for _, sig := range in.TaprootScriptSpendSig {
				args[hex.EncodeToString(sig.XOnlyPubKey)] = sig.Signature
			}

			witness, err := closure.Witness(in.TaprootLeafScript[0].ControlBlock, args)
			if err != nil {
				return "", err
			}

			var witnessBuf bytes.Buffer
			if err := psbt.WriteTxWitness(&witnessBuf, witness); err != nil {
				return "", err
			}

			ptx.Inputs[i].FinalScriptWitness = witnessBuf.Bytes()
			continue

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

func (b *txBuilder) VerifyForfeitTxs(vtxos []domain.Vtxo, connectors []string, forfeitTxs []string) (map[domain.VtxoKey][]string, error) {
	connectorsPtxs := make([]*psbt.Packet, 0, len(connectors))
	var connectorAmount uint64

	for i, connector := range connectors {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(connector), true)
		if err != nil {
			return nil, err
		}

		if i == len(connectors)-1 {
			lastOutput := ptx.UnsignedTx.TxOut[len(ptx.UnsignedTx.TxOut)-1]
			connectorAmount = uint64(lastOutput.Value)
		}

		connectorsPtxs = append(connectorsPtxs, ptx)
	}

	// decode forfeit txs, map by vtxo key
	forfeitTxsPtxs := make(map[domain.VtxoKey][]*psbt.Packet)
	for _, forfeitTx := range forfeitTxs {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(forfeitTx), true)
		if err != nil {
			return nil, err
		}

		if len(ptx.Inputs) != 2 {
			return nil, fmt.Errorf("invalid forfeit tx, expect 2 inputs, got %d", len(ptx.Inputs))
		}

		valid, err := b.verifyTapscriptPartialSigs(ptx)
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, fmt.Errorf("invalid forfeit tx signature")
		}

		vtxoInput := ptx.UnsignedTx.TxIn[1]

		vtxoKey := domain.VtxoKey{
			Txid: vtxoInput.PreviousOutPoint.Hash.String(),
			VOut: vtxoInput.PreviousOutPoint.Index,
		}
		if _, ok := forfeitTxsPtxs[vtxoKey]; !ok {
			forfeitTxsPtxs[vtxoKey] = make([]*psbt.Packet, 0)
		}
		forfeitTxsPtxs[vtxoKey] = append(forfeitTxsPtxs[vtxoKey], ptx)
	}

	forfeitAddress, err := b.wallet.GetForfeitAddress(context.Background())
	if err != nil {
		return nil, err
	}

	addr, err := btcutil.DecodeAddress(forfeitAddress, nil)
	if err != nil {
		return nil, err
	}

	forfeitScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, err
	}

	minRate := b.wallet.MinRelayFeeRate(context.Background())

	validForfeitTxs := make(map[domain.VtxoKey][]string)

	blocktimestamp, err := b.wallet.GetCurrentBlockTime(context.Background())
	if err != nil {
		return nil, err
	}

	for vtxoKey, ptxs := range forfeitTxsPtxs {
		if len(ptxs) == 0 {
			continue
		}

		var vtxo *domain.Vtxo
		for _, v := range vtxos {
			if v.VtxoKey == vtxoKey {
				vtxo = &v
				break
			}
		}

		if vtxo == nil {
			return nil, fmt.Errorf("missing vtxo %s", vtxoKey)
		}

		outputAmount := uint64(0)

		// only take the first forfeit tx, as all forfeit must have the same output
		firstForfeit := ptxs[0]
		for _, output := range firstForfeit.UnsignedTx.TxOut {
			outputAmount += uint64(output.Value)
		}

		inputAmount := vtxo.Amount + connectorAmount
		feeAmount := inputAmount - outputAmount

		if len(firstForfeit.Inputs[1].TaprootLeafScript) <= 0 {
			return nil, fmt.Errorf("missing taproot leaf script for vtxo input, invalid forfeit tx")
		}

		vtxoTapscript := firstForfeit.Inputs[1].TaprootLeafScript[0]
		conditionWitness, err := bitcointree.GetConditionWitness(firstForfeit.Inputs[1])
		if err != nil {
			return nil, err
		}
		conditionWitnessSize := 0
		for _, witness := range conditionWitness {
			conditionWitnessSize += len(witness)
		}

		// verify the forfeit closure script
		closure, err := tree.DecodeClosure(vtxoTapscript.Script)
		if err != nil {
			return nil, err
		}

		locktime := common.AbsoluteLocktime(0)

		switch c := closure.(type) {
		case *tree.CLTVMultisigClosure:
			locktime = c.Locktime
		case *tree.MultisigClosure, *tree.ConditionMultisigClosure:
		default:
			return nil, fmt.Errorf("invalid forfeit closure script")
		}

		if locktime != 0 {
			if !locktime.IsSeconds() {
				if locktime > common.AbsoluteLocktime(blocktimestamp.Height) {
					return nil, fmt.Errorf("forfeit closure is CLTV locked, %d > %d (block height)", locktime, blocktimestamp.Height)
				}
			} else {
				if locktime > common.AbsoluteLocktime(blocktimestamp.Time) {
					return nil, fmt.Errorf("forfeit closure is CLTV locked, %d > %d (block time)", locktime, blocktimestamp.Time)
				}
			}
		}

		ctrlBlock, err := txscript.ParseControlBlock(vtxoTapscript.ControlBlock)
		if err != nil {
			return nil, err
		}

		minFee, err := common.ComputeForfeitTxFee(
			minRate,
			&waddrmgr.Tapscript{
				RevealedScript: vtxoTapscript.Script,
				ControlBlock:   ctrlBlock,
			},
			closure.WitnessSize(conditionWitnessSize),
			txscript.GetScriptClass(forfeitScript),
		)
		if err != nil {
			return nil, err
		}

		dustAmount, err := b.wallet.GetDustAmount(context.Background())
		if err != nil {
			return nil, err
		}

		if inputAmount-feeAmount < dustAmount {
			return nil, fmt.Errorf("forfeit tx output amount is dust, %d < %d", inputAmount-feeAmount, dustAmount)
		}

		if feeAmount < uint64(minFee) {
			return nil, fmt.Errorf("forfeit tx fee is lower than the min relay fee, %d < %d", feeAmount, minFee)
		}

		feeThreshold := uint64(math.Ceil(float64(minFee) * 1.05))

		if feeAmount > feeThreshold {
			return nil, fmt.Errorf("forfeit tx fee is higher than 5%% of the min relay fee, %d > %d", feeAmount, feeThreshold)
		}

		vtxoChainhash, err := chainhash.NewHashFromStr(vtxoKey.Txid)
		if err != nil {
			return nil, err
		}

		vtxoInput := &wire.OutPoint{
			Hash:  *vtxoChainhash,
			Index: vtxoKey.VOut,
		}

		vtxoTapKey, err := vtxo.TapKey()
		if err != nil {
			return nil, err
		}

		vtxoScript, err := common.P2TRScript(vtxoTapKey)
		if err != nil {
			return nil, err
		}

		rebuiltForfeits := make([]*psbt.Packet, 0)

		for _, connector := range connectorsPtxs {
			forfeits, err := bitcointree.BuildForfeitTxs(
				connector,
				vtxoInput,
				vtxo.Amount,
				connectorAmount,
				feeAmount,
				vtxoScript,
				forfeitScript,
				uint32(locktime),
			)
			if err != nil {
				return nil, err
			}

			rebuiltForfeits = append(rebuiltForfeits, forfeits...)
		}

		if len(rebuiltForfeits) != len(ptxs) {
			return nil, fmt.Errorf("missing forfeits, expect %d, got %d", len(ptxs), len(rebuiltForfeits))
		}

		for _, forfeit := range rebuiltForfeits {
			found := false
			txid := forfeit.UnsignedTx.TxHash().String()
			for _, ptx := range ptxs {
				if txid == ptx.UnsignedTx.TxHash().String() {
					found = true
					break
				}
			}

			if !found {
				return nil, fmt.Errorf("missing forfeit tx %s", txid)
			}
		}

		b64Txs := make([]string, 0, len(ptxs))
		for _, forfeit := range ptxs {
			b64, err := forfeit.B64Encode()
			if err != nil {
				return nil, err
			}

			b64Txs = append(b64Txs, b64)
		}

		validForfeitTxs[vtxoKey] = b64Txs
	}

	return validForfeitTxs, nil
}

func (b *txBuilder) BuildRoundTx(
	serverPubkey *secp256k1.PublicKey,
	requests []domain.TxRequest,
	boardingInputs []ports.BoardingInput,
	connectorAddresses []string,
	cosigners ...*secp256k1.PublicKey,
) (roundTx string, vtxoTree tree.VtxoTree, nextConnectorAddress string, connectors []string, err error) {
	var sharedOutputScript []byte
	var sharedOutputAmount int64

	if len(cosigners) == 0 {
		return "", nil, "", nil, fmt.Errorf("missing cosigners")
	}

	receivers, err := getOutputVtxosLeaves(requests)
	if err != nil {
		return "", nil, "", nil, err
	}

	feeAmount, err := b.minRelayFeeTreeTx()
	if err != nil {
		return
	}

	if !isOnchainOnly(requests) {
		sharedOutputScript, sharedOutputAmount, err = bitcointree.CraftSharedOutput(
			cosigners, serverPubkey, receivers, feeAmount, b.vtxoTreeExpiry,
		)
		if err != nil {
			return
		}
	}

	nextConnectorAddress, err = b.wallet.DeriveConnectorAddress(context.Background())
	if err != nil {
		return
	}

	ptx, err := b.createRoundTx(
		sharedOutputAmount, sharedOutputScript, requests,
		boardingInputs, nextConnectorAddress, connectorAddresses,
	)
	if err != nil {
		return
	}

	roundTx, err = ptx.B64Encode()
	if err != nil {
		return
	}

	if !isOnchainOnly(requests) {
		initialOutpoint := &wire.OutPoint{
			Hash:  ptx.UnsignedTx.TxHash(),
			Index: 0,
		}

		vtxoTree, err = bitcointree.BuildVtxoTree(
			initialOutpoint, cosigners, serverPubkey, receivers, feeAmount, b.vtxoTreeExpiry,
		)
		if err != nil {
			return "", nil, "", nil, err
		}
	}

	if countSpentVtxos(requests) <= 0 {
		return
	}

	connectorAddr, err := btcutil.DecodeAddress(nextConnectorAddress, b.onchainNetwork())
	if err != nil {
		return "", nil, "", nil, err
	}

	connectorPkScript, err := txscript.PayToAddrScript(connectorAddr)
	if err != nil {
		return "", nil, "", nil, err
	}

	minRelayFeeConnectorTx, err := b.minRelayFeeConnectorTx()
	if err != nil {
		return "", nil, "", nil, err
	}

	connectorsPsbts, err := b.createConnectors(roundTx, requests, connectorPkScript, minRelayFeeConnectorTx)
	if err != nil {
		return "", nil, "", nil, err
	}

	for _, ptx := range connectorsPsbts {
		b64, err := ptx.B64Encode()
		if err != nil {
			return "", nil, "", nil, err
		}
		connectors = append(connectors, b64)
	}

	return roundTx, vtxoTree, nextConnectorAddress, connectors, nil
}

func (b *txBuilder) GetSweepInput(node tree.Node) (vtxoTreeExpiry *common.RelativeLocktime, sweepInput ports.SweepInput, err error) {
	partialTx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
	if err != nil {
		return nil, nil, err
	}

	if len(partialTx.Inputs) != 1 {
		return nil, nil, fmt.Errorf("invalid node pset, expect 1 input, got %d", len(partialTx.Inputs))
	}

	input := partialTx.UnsignedTx.TxIn[0]
	txid := input.PreviousOutPoint.Hash
	index := input.PreviousOutPoint.Index

	sweepLeaf, internalKey, vtxoTreeExpiry, err := extractSweepLeaf(partialTx.Inputs[0])
	if err != nil {
		return nil, nil, err
	}

	txhex, err := b.wallet.GetTransaction(context.Background(), txid.String())
	if err != nil {
		return nil, nil, err
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txhex))); err != nil {
		return nil, nil, err
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

	return vtxoTreeExpiry, sweepInput, nil
}

func (b *txBuilder) FindLeaves(vtxoTree tree.VtxoTree, fromtxid string, vout uint32) ([]tree.Node, error) {
	allLeaves := vtxoTree.Leaves()
	foundLeaves := make([]tree.Node, 0)

	for _, leaf := range allLeaves {
		branch, err := vtxoTree.Branch(leaf.Txid)
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

// TODO use lnd CoinSelect to craft the pool tx
func (b *txBuilder) createRoundTx(
	sharedOutputAmount int64,
	sharedOutputScript []byte,
	requests []domain.TxRequest,
	boardingInputs []ports.BoardingInput,
	nextConnectorAddress string,
	connectorAddresses []string,
) (*psbt.Packet, error) {
	nextConnectorAddr, err := btcutil.DecodeAddress(nextConnectorAddress, b.onchainNetwork())
	if err != nil {
		return nil, err
	}

	nextConnectorScript, err := txscript.PayToAddrScript(nextConnectorAddr)
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

	nbOfInputs := countSpentVtxos(requests)
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
			PkScript: nextConnectorScript,
		})
	}

	onchainOutputs, err := getOnchainOutputs(requests, b.onchainNetwork())
	if err != nil {
		return nil, err
	}

	for _, output := range onchainOutputs {
		targetAmount += uint64(output.Value)
	}

	outputs = append(outputs, onchainOutputs...)

	for _, input := range boardingInputs {
		targetAmount -= input.Amount
	}

	ctx := context.Background()
	utxos, change, err := b.selectUtxos(ctx, connectorAddresses, targetAmount)
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

		boardingVtxoScript, err := bitcointree.ParseVtxoScript(boardingInput.Tapscripts)
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
			preimage, err := b.getTaprootPreimage(sourceTx, i, sourceInput.TaprootLeafScript[0].Script)
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
	roundTx string, requests []domain.TxRequest, connectorScript []byte, feeAmount uint64,
) ([]*psbt.Packet, error) {
	partialTx, err := psbt.NewFromRawBytes(strings.NewReader(roundTx), true)
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

	numberOfConnectors := countSpentVtxos(requests)

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

func (b *txBuilder) selectUtxos(
	ctx context.Context, connectorAddresses []string, amount uint64,
) ([]ports.TxInput, uint64, error) {
	selectedConnectorsUtxos := make([]ports.TxInput, 0)
	selectedConnectorsAmount := uint64(0)

	for _, addr := range connectorAddresses {
		if selectedConnectorsAmount >= amount {
			break
		}
		connectors, err := b.wallet.ListConnectorUtxos(ctx, addr)
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

func (b *txBuilder) getTaprootPreimage(partial *psbt.Packet, inputIndex int, leafScript []byte) ([]byte, error) {
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
	switch b.net.Name {
	case common.Bitcoin.Name:
		return &chaincfg.MainNetParams
	//case common.BitcoinTestNet4.Name: //TODO uncomment once supported
	//return common.TestNet4Params
	case common.BitcoinTestNet.Name:
		return &chaincfg.TestNet3Params
	case common.BitcoinSigNet.Name:
		return &chaincfg.SigNetParams
	case common.BitcoinMutinyNet.Name:
		return &common.MutinyNetSigNetParams
	case common.BitcoinRegTest.Name:
		return &chaincfg.RegressionNetParams
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

func extractSweepLeaf(input psbt.PInput) (sweepLeaf *psbt.TaprootTapLeafScript, internalKey *secp256k1.PublicKey, vtxoTreeExpiry *common.RelativeLocktime, err error) {
	for _, leaf := range input.TaprootLeafScript {
		closure := &tree.CSVMultisigClosure{}
		valid, err := closure.Decode(leaf.Script)
		if err != nil {
			return nil, nil, nil, err
		}

		if valid && (vtxoTreeExpiry == nil || closure.Locktime.LessThan(*vtxoTreeExpiry)) {
			sweepLeaf = leaf
			vtxoTreeExpiry = &closure.Locktime
		}
	}

	internalKey, err = schnorr.ParsePubKey(input.TaprootInternalKey)
	if err != nil {
		return nil, nil, nil, err
	}

	if sweepLeaf == nil {
		return nil, nil, nil, fmt.Errorf("sweep leaf not found")
	}

	return sweepLeaf, internalKey, vtxoTreeExpiry, nil
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
