package txbuilder

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"runtime"
	"strings"
	"sync"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
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
	wallet ports.WalletService,
	net common.Network,
	vtxoTreeExpiry, boardingExitDelay common.RelativeLocktime,
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
		tapKeyFromControlBlock := txscript.ComputeTaprootOutputKey(
			bitcointree.UnspendableKey(), rootHash[:],
		)
		pkscript, err := common.P2TRScript(tapKeyFromControlBlock)
		if err != nil {
			return false, err
		}

		if !bytes.Equal(pkscript, input.WitnessUtxo.PkScript) {
			return false, fmt.Errorf("invalid control block for input %d", index)
		}

		preimage, err := b.getTaprootPreimage(ptx, index, tapLeaf.Script)
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

func (b *txBuilder) VerifyForfeitTxs(
	vtxos []domain.Vtxo, connectors []string, forfeitTxs []string,
) (map[domain.VtxoKey][]string, error) {
	connectorTxs, connectorAmount, err := parseConnectors(connectors)
	if err != nil {
		return nil, err
	}

	// decode forfeit txs, map by vtxo key
	indexedForfeitTxs := make(map[domain.VtxoKey]*struct {
		firstTx *psbt.Packet
		txs     map[string]*psbt.Packet
	})
	for _, forfeitTx := range forfeitTxs {
		tx, err := psbt.NewFromRawBytes(strings.NewReader(forfeitTx), true)
		if err != nil {
			return nil, err
		}

		if len(tx.Inputs) != 2 {
			return nil, fmt.Errorf("invalid forfeit tx, expect 2 inputs, got %d", len(tx.Inputs))
		}

		txid := tx.UnsignedTx.TxHash().String()
		vtxoInput := tx.UnsignedTx.TxIn[1]
		vtxoKey := domain.VtxoKey{
			Txid: vtxoInput.PreviousOutPoint.Hash.String(),
			VOut: vtxoInput.PreviousOutPoint.Index,
		}
		if _, ok := indexedForfeitTxs[vtxoKey]; !ok {
			indexedForfeitTxs[vtxoKey] = &struct {
				firstTx *psbt.Packet
				txs     map[string]*psbt.Packet
			}{firstTx: tx, txs: make(map[string]*psbt.Packet)}
		}
		indexedForfeitTxs[vtxoKey].txs[txid] = tx
	}

	indexedVtxos := map[domain.VtxoKey]domain.Vtxo{}
	for _, vtxo := range vtxos {
		indexedVtxos[vtxo.VtxoKey] = vtxo
	}

	forfeitScript, err := b.getForfeitScript()
	if err != nil {
		return nil, err
	}

	minRate := b.wallet.MinRelayFeeRate(context.Background())

	blocktimestamp, err := b.wallet.GetCurrentBlockTime(context.Background())
	if err != nil {
		return nil, err
	}

	dustAmount, err := b.wallet.GetDustAmount(context.Background())
	if err != nil {
		return nil, err
	}

	validForfeitTxs := make(map[domain.VtxoKey][]string)

	for vtxoKey, f := range indexedForfeitTxs {
		if len(f.txs) == 0 {
			continue
		}

		if err := b.verifyTapscriptPartialSigsMap(f.txs); err != nil {
			return nil, err
		}

		vtxo, ok := indexedVtxos[vtxoKey]
		if !ok {
			return nil, fmt.Errorf("missing vtxo %s", vtxoKey)
		}

		outputAmount := uint64(0)

		// only take the first forfeit tx, as all forfeit must have the same output
		firstForfeit := f.firstTx
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

		rebuiltTxIds := make(map[string]bool)

		nbWorkers := runtime.NumCPU()
		jobsConnector := make(chan *psbt.Packet, len(connectorTxs))
		errChan := make(chan error, 1)
		m := &sync.Mutex{}
		wg := sync.WaitGroup{}
		wg.Add(nbWorkers)

		// start work pool
		for i := 0; i < nbWorkers; i++ {
			go func(m *sync.Mutex) {
				defer wg.Done()

				for connector := range jobsConnector {
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
						errChan <- err
						return
					}

					m.Lock()
					for _, forfeit := range forfeits {
						txid := forfeit.UnsignedTx.TxHash().String()
						rebuiltTxIds[txid] = true
					}
					m.Unlock()
				}
			}(m)
		}

		for _, connector := range connectorTxs {
			select {
			// don't wait for the whole jobs pool to be done in case of error
			case err := <-errChan:
				return nil, err
			default:
				jobsConnector <- connector
			}
		}

		close(jobsConnector)
		// wait for the workers
		wg.Wait()

		select {
		case err := <-errChan:
			return nil, err
		default:
			close(errChan)
		}

		if len(rebuiltTxIds) != len(f.txs) {
			return nil, fmt.Errorf("missing forfeits, expect %d, got %d", len(f.txs), len(rebuiltTxIds))
		}

		// verify all rebuilt are the same as the original forfeits
		for txid := range rebuiltTxIds {
			if _, ok := f.txs[txid]; !ok {
				return nil, fmt.Errorf("missing forfeit tx %s", txid)
			}
		}

		b64Txs := make([]string, 0, len(f.txs))
		for _, forfeit := range f.txs {
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
	musig2Data []*tree.Musig2,
) (roundTx string, vtxoTree tree.VtxoTree, nextConnectorAddress string, connectors []string, err error) {
	var sharedOutputScript []byte
	var sharedOutputAmount int64

	receivers, err := getOutputVtxosLeaves(requests, musig2Data)
	if err != nil {
		return "", nil, "", nil, err
	}

	feeAmount, err := b.minRelayFeeTreeTx()
	if err != nil {
		return
	}

	var sweepScript []byte
	sweepScript, err = (&tree.CSVMultisigClosure{
		MultisigClosure: tree.MultisigClosure{
			PubKeys: []*secp256k1.PublicKey{serverPubkey},
		},
		Locktime: b.vtxoTreeExpiry,
	}).Script()
	if err != nil {
		return
	}

	tree := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(sweepScript))
	root := tree.RootNode.TapHash()

	if !isOnchainOnly(requests) {
		sharedOutputScript, sharedOutputAmount, err = bitcointree.CraftSharedOutput(
			receivers, feeAmount, root[:],
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
			initialOutpoint, receivers, feeAmount, root[:], b.vtxoTreeExpiry,
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

	sweepLeaf, internalKey, vtxoTreeExpiry, err := b.extractSweepLeaf(partialTx.Inputs[0])
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

func (b *txBuilder) BuildSweepEarlyTx(roundID string, node tree.Node, vtxoTreeKeys []domain.RawKeyPair) (string, error) {
	tx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
	if err != nil {
		return "", err
	}

	inputToSweep := tx.Inputs[0]

	cosignerPubKeys, err := bitcointree.GetCosignerKeys(inputToSweep)
	if err != nil {
		return "", err
	}

	ctx := context.Background()

	signerSession, err := b.wallet.GetVtxoTreeSignerSession(ctx, roundID)
	if err != nil {
		return "", err
	}
	serverPrvKey := signerSession.GetSecretKey()
	serverPubkey := serverPrvKey.PubKey().SerializeCompressed()

	privKeys := make([]*secp256k1.PrivateKey, 0, len(cosignerPubKeys))

	for _, pubkey := range cosignerPubKeys {
		found := false
		pubkeyBytes := pubkey.SerializeCompressed()

		if bytes.Equal(pubkeyBytes, serverPubkey) {
			privKeys = append(privKeys, serverPrvKey)
			continue
		}

		for _, key := range vtxoTreeKeys {
			if bytes.Equal(key.Pubkey, pubkey.SerializeCompressed()) {
				privKey := secp256k1.PrivKeyFromBytes(key.Seckey)
				privKeys = append(privKeys, privKey)
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("missing secret key for cosigner pubkey %x", pubkey.SerializeCompressed())
		}
	}

	vtxoTreeExpiry, err := bitcointree.GetVtxoTreeExpiry(inputToSweep)
	if err != nil {
		return "", err
	}

	serverPubKey, err := b.wallet.GetPubkey(context.Background())
	if err != nil {
		return "", err
	}

	sweepClosure := &tree.CSVMultisigClosure{
		Locktime: *vtxoTreeExpiry,
		MultisigClosure: tree.MultisigClosure{
			PubKeys: []*secp256k1.PublicKey{serverPubKey},
		},
	}

	sweepScript, err := sweepClosure.Script()
	if err != nil {
		return "", err
	}

	sweepRoot := txscript.NewBaseTapLeaf(sweepScript).TapHash()

	aggregatedKey, err := bitcointree.AggregateKeys(cosignerPubKeys, sweepRoot[:])
	if err != nil {
		return "", err
	}

	addresses, err := b.wallet.DeriveAddresses(context.Background(), 1)
	if err != nil {
		return "", err
	}

	addr, err := btcutil.DecodeAddress(addresses[0], b.onchainNetwork())
	if err != nil {
		return "", err
	}

	outputScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return "", err
	}

	inputAmount := int64(0)

	for _, out := range tx.UnsignedTx.TxOut {
		inputAmount += out.Value
	}

	treeTxFee, err := b.wallet.MinRelayFee(context.Background(), uint64(common.TreeTxSize))
	if err != nil {
		return "", err
	}

	inputAmount -= int64(treeTxFee)

	outpoint := tx.UnsignedTx.TxIn[0].PreviousOutPoint
	ptx, err := psbt.New(
		[]*wire.OutPoint{&outpoint},
		[]*wire.TxOut{{
			Value:    int64(inputAmount),
			PkScript: outputScript,
		}},
		2,
		0,
		[]uint32{wire.MaxTxInSequenceNum},
	)
	if err != nil {
		return "", err
	}

	ptx.Inputs[0].WitnessUtxo = inputToSweep.WitnessUtxo
	ptx.Inputs[0].TaprootInternalKey = schnorr.SerializePubKey(aggregatedKey.PreTweakedKey)
	ptx.Inputs[0].TaprootMerkleRoot = sweepRoot[:]

	b64, err := ptx.B64Encode()
	if err != nil {
		return "", err
	}

	fees, err := b.wallet.EstimateFees(context.Background(), b64)
	if err != nil {
		return "", err
	}

	ptx.UnsignedTx.TxOut[0].Value = inputAmount - int64(fees)

	// sign using musig2
	nonces := make([]*musig2.Nonces, 0, len(privKeys))
	publicNonces := make([][66]byte, 0, len(privKeys))

	for _, privKey := range privKeys {
		nonces, err := musig2.GenNonces(musig2.WithPublicKey(privKey.PubKey()))
		if err != nil {
			return "", err
		}

		publicNonces = append(publicNonces, nonces.PubNonce)
	}

	combinedNonces, err := musig2.AggregateNonces(publicNonces)
	if err != nil {
		return "", err
	}

	prevouts := make(map[wire.OutPoint]*wire.TxOut)

	inputScriptPubKey, err := common.P2TRScript(aggregatedKey.FinalKey)
	if err != nil {
		return "", err
	}

	prevouts[ptx.UnsignedTx.TxIn[0].PreviousOutPoint] = &wire.TxOut{
		Value:    int64(inputAmount),
		PkScript: inputScriptPubKey,
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)

	message, err := txscript.CalcTaprootSignatureHash(
		txscript.NewTxSigHashes(ptx.UnsignedTx, prevoutFetcher),
		txscript.SigHashDefault,
		ptx.UnsignedTx,
		0,
		prevoutFetcher,
	)
	if err != nil {
		return "", err
	}

	partialSigs := make([]*musig2.PartialSignature, 0, len(privKeys))

	for i, privKey := range privKeys {
		secNonce := nonces[i].SecNonce

		partialSig, err := musig2.Sign(
			secNonce, privKey, combinedNonces, cosignerPubKeys, [32]byte(message),
			musig2.WithSortedKeys(), musig2.WithTaprootSignTweak(sweepRoot[:]), musig2.WithFastSign(),
		)
		if err != nil {
			return "", err
		}

		partialSigs = append(partialSigs, partialSig)
	}

	combinedSig := musig2.CombineSigs(
		partialSigs[0].R, partialSigs,
		musig2.WithTaprootTweakedCombine([32]byte(message), cosignerPubKeys, sweepRoot[:], true),
	)

	ptx.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{{
		Signature:   combinedSig.Serialize(),
		XOnlyPubKey: schnorr.SerializePubKey(aggregatedKey.FinalKey),
	}}

	if err := psbt.Finalize(ptx, 0); err != nil {
		return "", err
	}

	finalized, err := psbt.Extract(ptx)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := finalized.Serialize(&buf); err != nil {
		return "", err
	}

	txHex := hex.EncodeToString(buf.Bytes())
	return b.wallet.BroadcastTransaction(ctx, txHex)
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

func (b *txBuilder) extractSweepLeaf(input psbt.PInput) (sweepLeaf *psbt.TaprootTapLeafScript, internalKey *secp256k1.PublicKey, vtxoTreeExpiry *common.RelativeLocktime, err error) {
	// this if case is here to handle previous version of the tree
	if len(input.TaprootLeafScript) > 0 {
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

	serverPubKey, err := b.wallet.GetPubkey(context.Background())
	if err != nil {
		return nil, nil, nil, err
	}

	cosignerPubKeys, err := bitcointree.GetCosignerKeys(input)
	if err != nil {
		return nil, nil, nil, err
	}

	if len(cosignerPubKeys) == 0 {
		return nil, nil, nil, fmt.Errorf("no cosigner pubkeys found")
	}

	vtxoTreeExpiry, err = bitcointree.GetVtxoTreeExpiry(input)
	if err != nil {
		return nil, nil, nil, err
	}

	sweepClosure := &tree.CSVMultisigClosure{
		Locktime: *vtxoTreeExpiry,
		MultisigClosure: tree.MultisigClosure{
			PubKeys: []*secp256k1.PublicKey{serverPubKey},
		},
	}

	sweepScript, err := sweepClosure.Script()
	if err != nil {
		return nil, nil, nil, err
	}

	sweepTapTree := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(sweepScript))
	sweepRoot := sweepTapTree.RootNode.TapHash()

	aggregatedKey, err := bitcointree.AggregateKeys(cosignerPubKeys, sweepRoot[:])
	if err != nil {
		return nil, nil, nil, err
	}
	internalKey = aggregatedKey.PreTweakedKey

	sweepLeafMerkleProof := sweepTapTree.LeafMerkleProofs[0]
	sweepLeafControlBlock := sweepLeafMerkleProof.ToControlBlock(internalKey)
	sweepLeafControlBlockBytes, err := sweepLeafControlBlock.ToBytes()
	if err != nil {
		return nil, nil, nil, err
	}

	sweepLeaf = &psbt.TaprootTapLeafScript{
		Script:       sweepScript,
		ControlBlock: sweepLeafControlBlockBytes,
		LeafVersion:  txscript.BaseLeafVersion,
	}

	return sweepLeaf, internalKey, vtxoTreeExpiry, nil
}

func (b *txBuilder) getForfeitScript() ([]byte, error) {
	forfeitAddress, err := b.wallet.GetForfeitAddress(context.Background())
	if err != nil {
		return nil, err
	}

	addr, err := btcutil.DecodeAddress(forfeitAddress, nil)
	if err != nil {
		return nil, err
	}

	return txscript.PayToAddrScript(addr)
}

func (b *txBuilder) verifyTapscriptPartialSigsMap(txs map[string]*psbt.Packet) error {
	nbWorkers := runtime.NumCPU()
	jobs := make(chan *psbt.Packet, len(txs))
	errChan := make(chan error, 1)
	wg := sync.WaitGroup{}
	wg.Add(nbWorkers)

	for i := 0; i < nbWorkers; i++ {
		go func() {
			defer wg.Done()

			for tx := range jobs {
				valid, err := b.verifyTapscriptPartialSigs(tx)
				if err != nil {
					errChan <- err
					return
				}

				if !valid {
					errChan <- fmt.Errorf("invalid forfeit tx signature (%s)", tx.UnsignedTx.TxHash().String())
					return
				}
			}
		}()
	}

	for _, tx := range txs {
		select {
		case err := <-errChan:
			return err
		default:
			jobs <- tx
		}
	}
	close(jobs)
	wg.Wait()

	select {
	case err := <-errChan:
		return err
	default:
		close(errChan)
		return nil
	}
}

func parseConnectors(connectors []string) ([]*psbt.Packet, uint64, error) {
	var connectorAmount uint64
	connectorTxs := make([]*psbt.Packet, 0, len(connectors))
	for i, connector := range connectors {
		tx, err := psbt.NewFromRawBytes(strings.NewReader(connector), true)
		if err != nil {
			return nil, 0, err
		}

		if i == len(connectors)-1 {
			lastOutput := tx.UnsignedTx.TxOut[len(tx.UnsignedTx.TxOut)-1]
			connectorAmount = uint64(lastOutput.Value)
		}

		connectorTxs = append(connectorTxs, tx)
	}

	return connectorTxs, connectorAmount, nil
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
