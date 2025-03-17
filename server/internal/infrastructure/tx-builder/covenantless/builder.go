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

func (b *txBuilder) VerifyTapscriptPartialSigs(tx string) (bool, string, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return false, "", err
	}

	return b.verifyTapscriptPartialSigs(ptx)
}

func (b *txBuilder) verifyTapscriptPartialSigs(ptx *psbt.Packet) (bool, string, error) {
	txid := ptx.UnsignedTx.TxID()

	serverPubkey, err := b.wallet.GetPubkey(context.Background())
	if err != nil {
		return false, txid, err
	}

	for index, input := range ptx.Inputs {
		if len(input.TaprootLeafScript) == 0 {
			continue
		}

		if input.WitnessUtxo == nil {
			return false, txid, fmt.Errorf("missing prevout for input %d", index)
		}

		// verify taproot leaf script
		tapLeaf := input.TaprootLeafScript[0]

		closure, err := tree.DecodeClosure(tapLeaf.Script)
		if err != nil {
			return false, txid, err
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
				return false, txid, err
			}

			result, err := tree.ExecuteBoolScript(c.Condition, witness)
			if err != nil {
				return false, txid, err
			}

			if !result {
				return false, txid, fmt.Errorf("condition not met for input %d", index)
			}

			for _, key := range c.PubKeys {
				keys[hex.EncodeToString(schnorr.SerializePubKey(key))] = false
			}
		}

		// we don't need to check if server signed
		keys[hex.EncodeToString(schnorr.SerializePubKey(serverPubkey))] = true

		if len(tapLeaf.ControlBlock) == 0 {
			return false, txid, fmt.Errorf("missing control block for input %d", index)
		}

		controlBlock, err := txscript.ParseControlBlock(tapLeaf.ControlBlock)
		if err != nil {
			return false, txid, err
		}

		rootHash := controlBlock.RootHash(tapLeaf.Script)
		tapKeyFromControlBlock := txscript.ComputeTaprootOutputKey(
			bitcointree.UnspendableKey(), rootHash[:],
		)
		pkscript, err := common.P2TRScript(tapKeyFromControlBlock)
		if err != nil {
			return false, txid, err
		}

		if !bytes.Equal(pkscript, input.WitnessUtxo.PkScript) {
			return false, txid, fmt.Errorf("invalid control block for input %d", index)
		}

		preimage, err := b.getTaprootPreimage(ptx, index, tapLeaf.Script)
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
				return false, txid, nil
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
			return false, txid, fmt.Errorf("missing %d signatures", missingSigs)
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

func (b *txBuilder) BuildSweepTx(inputs []ports.SweepInput) (txid, signedSweepTx string, err error) {
	sweepPsbt, err := sweepTransaction(
		b.wallet,
		inputs,
	)
	if err != nil {
		return "", "", err
	}

	sweepPsbtBase64, err := sweepPsbt.B64Encode()
	if err != nil {
		return "", "", err
	}

	ctx := context.Background()
	signedSweepPsbtB64, err := b.wallet.SignTransactionTapscript(ctx, sweepPsbtBase64, nil)
	if err != nil {
		return "", "", err
	}

	signedPsbt, err := psbt.NewFromRawBytes(strings.NewReader(signedSweepPsbtB64), true)
	if err != nil {
		return "", "", err
	}

	for i := range inputs {
		if err := psbt.Finalize(signedPsbt, i); err != nil {
			return "", "", err
		}
	}

	tx, err := psbt.Extract(signedPsbt)
	if err != nil {
		return "", "", err
	}

	buf := new(bytes.Buffer)

	if err := tx.Serialize(buf); err != nil {
		return "", "", err
	}

	return tx.TxHash().String(), hex.EncodeToString(buf.Bytes()), nil
}

func (b *txBuilder) VerifyForfeitTxs(
	vtxos []domain.Vtxo, connectors tree.TxTree,
	forfeitTxs []string, connectorIndex map[string]domain.Outpoint,
) (map[domain.VtxoKey]string, error) {
	connectorsLeaves := connectors.Leaves()
	if len(connectorsLeaves) == 0 {
		return nil, fmt.Errorf("invalid connectors tree")
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

	validForfeitTxs := make(map[domain.VtxoKey]string)

	for _, forfeitTx := range forfeitTxs {
		tx, err := psbt.NewFromRawBytes(strings.NewReader(forfeitTx), true)
		if err != nil {
			return nil, err
		}

		if len(tx.Inputs) != 2 {
			continue
		}

		connectorInput := tx.UnsignedTx.TxIn[0]
		vtxoInput := tx.UnsignedTx.TxIn[1]

		vtxoKey := domain.VtxoKey{
			Txid: vtxoInput.PreviousOutPoint.Hash.String(),
			VOut: vtxoInput.PreviousOutPoint.Index,
		}

		expectedConnectorOutpoint, ok := connectorIndex[vtxoKey.String()]
		if !ok {
			return nil, fmt.Errorf("invalid connector outpoint for vtxo %s", vtxoKey)
		}

		if connectorInput.PreviousOutPoint.Hash.String() != expectedConnectorOutpoint.Txid ||
			connectorInput.PreviousOutPoint.Index != expectedConnectorOutpoint.VOut {
			return nil, fmt.Errorf(
				"invalid connector outpoint for vtxo %s, wrong outpoint, expected %s",
				vtxoKey,
				domain.VtxoKey(expectedConnectorOutpoint),
			)
		}

		if _, ok := validForfeitTxs[vtxoKey]; ok {
			continue
		}

		vtxo, ok := indexedVtxos[vtxoKey]
		if !ok {
			return nil, fmt.Errorf("missing vtxo %s", vtxoKey)
		}

		outputAmount := uint64(0)

		for _, output := range tx.UnsignedTx.TxOut {
			outputAmount += uint64(output.Value)
		}

		var connectorOutput *wire.TxOut
		for _, leaf := range connectorsLeaves {
			if leaf.Txid == connectorInput.PreviousOutPoint.Hash.String() {
				connectorTx, err := psbt.NewFromRawBytes(strings.NewReader(leaf.Tx), true)
				if err != nil {
					return nil, err
				}

				if len(connectorTx.UnsignedTx.TxOut) <= int(connectorInput.PreviousOutPoint.Index) {
					return nil, fmt.Errorf("invalid connector tx")
				}

				connectorOutput = connectorTx.UnsignedTx.TxOut[connectorInput.PreviousOutPoint.Index]
				break
			}
		}

		if connectorOutput == nil {
			return nil, fmt.Errorf("missing connector output")
		}

		inputAmount := vtxo.Amount + uint64(connectorOutput.Value)
		feeAmount := inputAmount - outputAmount

		if len(tx.Inputs[1].TaprootLeafScript) <= 0 {
			return nil, fmt.Errorf("missing taproot leaf script for vtxo input, invalid forfeit tx")
		}

		vtxoTapscript := tx.Inputs[1].TaprootLeafScript[0]
		conditionWitness, err := bitcointree.GetConditionWitness(tx.Inputs[1])
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

		vtxoTapKey, err := vtxo.TapKey()
		if err != nil {
			return nil, err
		}

		vtxoScript, err := common.P2TRScript(vtxoTapKey)
		if err != nil {
			return nil, err
		}

		rebuilt, err := bitcointree.BuildForfeitTx(
			&wire.OutPoint{
				Hash:  connectorInput.PreviousOutPoint.Hash,
				Index: connectorInput.PreviousOutPoint.Index,
			},
			&wire.OutPoint{
				Hash:  vtxoInput.PreviousOutPoint.Hash,
				Index: vtxoInput.PreviousOutPoint.Index,
			},
			vtxo.Amount,
			uint64(connectorOutput.Value),
			feeAmount,
			vtxoScript,
			connectorOutput.PkScript,
			forfeitScript,
			uint32(locktime),
		)
		if err != nil {
			return nil, err
		}

		if rebuilt.UnsignedTx.TxID() != tx.UnsignedTx.TxID() {
			return nil, fmt.Errorf("invalid forfeit tx")
		}

		validForfeitTxs[vtxoKey] = forfeitTx
	}

	return validForfeitTxs, nil
}

func (b *txBuilder) BuildRoundTx(
	serverPubkey *secp256k1.PublicKey,
	requests []domain.TxRequest,
	boardingInputs []ports.BoardingInput,
	connectorAddresses []string,
	musig2Data []*tree.Musig2,
) (string, tree.TxTree, string, tree.TxTree, error) {
	var sharedOutputScript []byte
	var sharedOutputAmount int64

	receivers, err := getOutputVtxosLeaves(requests, musig2Data)
	if err != nil {
		return "", nil, "", nil, err
	}

	feeAmount, err := b.minRelayFeeTreeTx()
	if err != nil {
		return "", nil, "", nil, err
	}

	sweepScript, err := (&tree.CSVMultisigClosure{
		MultisigClosure: tree.MultisigClosure{
			PubKeys: []*secp256k1.PublicKey{serverPubkey},
		},
		Locktime: b.vtxoTreeExpiry,
	}).Script()
	if err != nil {
		return "", nil, "", nil, err
	}

	sweepTapscriptRoot := txscript.NewBaseTapLeaf(sweepScript).TapHash()

	if !isOnchainOnly(requests) {
		sharedOutputScript, sharedOutputAmount, err = bitcointree.CraftSharedOutput(
			receivers, feeAmount, sweepTapscriptRoot[:],
		)
		if err != nil {
			return "", nil, "", nil, err
		}
	}

	nbOfConnectors := countSpentVtxos(requests)

	dustAmount, err := b.wallet.GetDustAmount(context.Background())
	if err != nil {
		return "", nil, "", nil, err
	}

	minRelayFeeConnectorTx, err := b.minRelayFeeConnectorTx()
	if err != nil {
		return "", nil, "", nil, err
	}

	var nextConnectorAddress string
	var connectorsTreePkScript []byte
	var connectorsTreeAmount int64
	connectorsTreeLeaves := make([]tree.Leaf, 0)

	if nbOfConnectors > 0 {
		nextConnectorAddress, err = b.wallet.DeriveConnectorAddress(context.Background())
		if err != nil {
			return "", nil, "", nil, err
		}

		connectorAddress, err := btcutil.DecodeAddress(nextConnectorAddress, b.onchainNetwork())
		if err != nil {
			return "", nil, "", nil, err
		}

		connectorPkScript, err := txscript.PayToAddrScript(connectorAddress)
		if err != nil {
			return "", nil, "", nil, err
		}

		// check if the connector script is a taproot script
		// we need taproot to properly create the connectors tree
		connectorScriptClass := txscript.GetScriptClass(connectorPkScript)
		if connectorScriptClass != txscript.WitnessV1TaprootTy {
			return "", nil, "", nil, fmt.Errorf("invalid connector script class, expected taproot (%s), got %s", txscript.WitnessV1TaprootTy, connectorScriptClass)
		}

		taprootKey, err := schnorr.ParsePubKey(connectorPkScript[2:])
		if err != nil {
			return "", nil, "", nil, err
		}

		cosigners := []string{hex.EncodeToString(taprootKey.SerializeCompressed())}

		for i := uint64(0); i < nbOfConnectors; i++ {
			connectorsTreeLeaves = append(connectorsTreeLeaves, tree.Leaf{
				Amount: uint64(dustAmount),
				Script: hex.EncodeToString(connectorPkScript),
				Musig2Data: &tree.Musig2{
					CosignersPublicKeys: cosigners,
					SigningType:         tree.SignBranch,
				},
			})
		}

		connectorsTreePkScript, connectorsTreeAmount, err = bitcointree.CraftConnectorsOutput(
			connectorsTreeLeaves,
			minRelayFeeConnectorTx,
		)
		if err != nil {
			return "", nil, "", nil, err
		}
	}

	ptx, err := b.createRoundTx(
		sharedOutputAmount, sharedOutputScript,
		connectorsTreeAmount, connectorsTreePkScript,
		requests, boardingInputs,
		connectorAddresses,
	)
	if err != nil {
		return "", nil, "", nil, err
	}

	roundTx, err := ptx.B64Encode()
	if err != nil {
		return "", nil, "", nil, err
	}

	vtxoTree := make(tree.TxTree, 0)

	if !isOnchainOnly(requests) {
		initialOutpoint := &wire.OutPoint{
			Hash:  ptx.UnsignedTx.TxHash(),
			Index: 0,
		}

		vtxoTree, err = bitcointree.BuildVtxoTree(
			initialOutpoint, receivers, feeAmount, sweepTapscriptRoot[:], b.vtxoTreeExpiry,
		)
		if err != nil {
			return "", nil, "", nil, err
		}
	}

	if nbOfConnectors <= 0 {
		return roundTx, vtxoTree, nextConnectorAddress, nil, nil
	}

	partialTx, err := psbt.NewFromRawBytes(strings.NewReader(roundTx), true)
	if err != nil {
		return "", nil, "", nil, err
	}

	rootConnectorsOutpoint := &wire.OutPoint{
		Hash:  partialTx.UnsignedTx.TxHash(),
		Index: 1,
	}

	connectors, err := bitcointree.BuildConnectorsTree(
		rootConnectorsOutpoint,
		connectorsTreeLeaves,
		minRelayFeeConnectorTx,
	)
	if err != nil {
		return "", nil, "", nil, err
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

func (b *txBuilder) FindLeaves(vtxoTree tree.TxTree, fromtxid string, vout uint32) ([]tree.Node, error) {
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

func (b *txBuilder) createRoundTx(
	sharedOutputAmount int64,
	sharedOutputScript []byte,
	connectorOutputAmount int64,
	connectorOutputScript []byte,
	requests []domain.TxRequest,
	boardingInputs []ports.BoardingInput,
	connectorAddresses []string,
) (*psbt.Packet, error) {
	dustLimit, err := b.wallet.GetDustAmount(context.Background())
	if err != nil {
		return nil, err
	}

	targetAmount := uint64(0)

	outputs := make([]*wire.TxOut, 0)

	if sharedOutputScript != nil && sharedOutputAmount > 0 {
		targetAmount += uint64(sharedOutputAmount)

		outputs = append(outputs, &wire.TxOut{
			Value:    sharedOutputAmount,
			PkScript: sharedOutputScript,
		})
	}

	if connectorOutputScript != nil && connectorOutputAmount > 0 {
		targetAmount += uint64(connectorOutputAmount)

		outputs = append(outputs, &wire.TxOut{
			Value:    connectorOutputAmount,
			PkScript: connectorOutputScript,
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

func (b *txBuilder) CountSignedTaprootInputs(tx string) (int, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return -1, err
	}

	signedInputsCount := 0
	for _, in := range ptx.Inputs {
		if len(in.TaprootScriptSpendSig) == 0 || len(in.TaprootLeafScript) == 0 {
			continue
		}

		signedInputsCount++
	}
	return signedInputsCount, nil
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

	for i, sourceInput := range sourceTx.Inputs {
		isMultisigTaproot := len(sourceInput.TaprootLeafScript) > 0
		if isMultisigTaproot {
			// check if the source tx signs the leaf
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
