package txbuilder

import (
	"bytes"
	"context"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
	"github.com/vulpemventures/go-elements/transaction"
)

type txBuilder struct {
	wallet            ports.WalletService
	net               common.Network
	roundLifetime     int64 // in seconds
	boardingExitDelay int64 // in seconds
}

func NewTxBuilder(
	wallet ports.WalletService,
	net common.Network,
	roundLifetime int64,
	boardingExitDelay int64,
) ports.TxBuilder {
	return &txBuilder{wallet, net, roundLifetime, boardingExitDelay}
}

func (b *txBuilder) GetTxID(tx string) (string, error) {
	return getTxid(tx)
}

func (b *txBuilder) BuildSweepTx(inputs []ports.SweepInput) (signedSweepTx string, err error) {
	sweepPset, err := sweepTransaction(
		b.wallet,
		inputs,
		b.onchainNetwork().AssetID,
	)
	if err != nil {
		return "", err
	}

	sweepPsetBase64, err := sweepPset.ToBase64()
	if err != nil {
		return "", err
	}

	ctx := context.Background()
	signedSweepPsetB64, err := b.wallet.SignTransactionTapscript(ctx, sweepPsetBase64, nil)
	if err != nil {
		return "", err
	}

	signedPset, err := psetv2.NewPsetFromBase64(signedSweepPsetB64)
	if err != nil {
		return "", err
	}

	if err := psetv2.FinalizeAll(signedPset); err != nil {
		return "", err
	}

	extractedTx, err := psetv2.Extract(signedPset)
	if err != nil {
		return "", err
	}

	return extractedTx.ToHex()
}

func (b *txBuilder) BuildForfeitTxs(
	poolTx string,
	payments []domain.Payment,
	minRelayFeeRate chainfee.SatPerKVByte,
) (connectors []string, forfeitTxs []string, err error) {
	connectorAddress, err := b.getConnectorAddress(poolTx)
	if err != nil {
		return nil, nil, err
	}

	connectorFeeAmount, err := b.minRelayFeeConnectorTx()
	if err != nil {
		return nil, nil, err
	}

	connectorAmount, err := b.wallet.GetDustAmount(context.Background())
	if err != nil {
		return nil, nil, err
	}

	connectorTxs, err := b.createConnectors(poolTx, payments, connectorAddress, connectorAmount, connectorFeeAmount)
	if err != nil {
		return nil, nil, err
	}

	forfeitTxs, err = b.createForfeitTxs(payments, connectorTxs, connectorAmount, minRelayFeeRate)
	if err != nil {
		return nil, nil, err
	}

	for _, tx := range connectorTxs {
		buf, _ := tx.ToBase64()
		connectors = append(connectors, buf)
	}
	return connectors, forfeitTxs, nil
}

func (b *txBuilder) BuildRoundTx(
	aspPubkey *secp256k1.PublicKey,
	payments []domain.Payment,
	boardingInputs []ports.BoardingInput,
	sweptRounds []domain.Round,
	_ ...*secp256k1.PublicKey, // cosigners are not used in the covenant
) (poolTx string, congestionTree tree.CongestionTree, connectorAddress string, err error) {
	// The creation of the tree and the pool tx are tightly coupled:
	// - building the tree requires knowing the shared outpoint (txid:vout)
	// - building the pool tx requires knowing the shared output script and amount
	// The idea here is to first create all the data for the outputs of the txs
	// of the congestion tree to calculate the shared output script and amount.
	// With these data the pool tx can be created, and once the shared utxo
	// outpoint is obtained, the congestion tree can be finally created.
	// The factory function `treeFactoryFn` returned below holds all outputs data
	// generated in the process and takes the shared utxo outpoint as argument.
	// This is safe as the memory allocated for `craftCongestionTree` is freed
	// only after `BuildPoolTx` returns.

	var sharedOutputScript []byte
	var sharedOutputAmount uint64
	var treeFactoryFn tree.TreeFactory

	if !isOnchainOnly(payments) {
		feeSatsPerNode, err := b.wallet.MinRelayFee(context.Background(), uint64(common.CovenantTreeTxSize))
		if err != nil {
			return "", nil, "", err
		}

		receivers, err := getOffchainReceivers(payments)
		if err != nil {
			return "", nil, "", err
		}

		treeFactoryFn, sharedOutputScript, sharedOutputAmount, err = tree.CraftCongestionTree(
			b.onchainNetwork().AssetID, aspPubkey, receivers, feeSatsPerNode, b.roundLifetime,
		)
		if err != nil {
			return "", nil, "", err
		}
	}

	connectorAddress, err = b.wallet.DeriveConnectorAddress(context.Background())
	if err != nil {
		return
	}

	ptx, err := b.createPoolTx(
		sharedOutputAmount, sharedOutputScript, payments, boardingInputs, aspPubkey, connectorAddress, sweptRounds,
	)
	if err != nil {
		return
	}

	unsignedTx, err := ptx.UnsignedTx()
	if err != nil {
		return
	}

	if treeFactoryFn != nil {
		congestionTree, err = treeFactoryFn(psetv2.InputArgs{
			Txid:    unsignedTx.TxHash().String(),
			TxIndex: 0,
		})
		if err != nil {
			return
		}
	}

	poolTx, err = ptx.ToBase64()
	if err != nil {
		return
	}

	return
}

func (b *txBuilder) GetSweepInput(node tree.Node) (lifetime int64, sweepInput ports.SweepInput, err error) {
	pset, err := psetv2.NewPsetFromBase64(node.Tx)
	if err != nil {
		return -1, nil, err
	}

	if len(pset.Inputs) != 1 {
		return -1, nil, fmt.Errorf("invalid node pset, expect 1 input, got %d", len(pset.Inputs))
	}

	// if the tx is not onchain, it means that the input is an existing shared output
	input := pset.Inputs[0]
	txid := chainhash.Hash(input.PreviousTxid).String()
	index := input.PreviousTxIndex

	sweepLeaf, lifetime, err := extractSweepLeaf(input)
	if err != nil {
		return -1, nil, err
	}

	txhex, err := b.wallet.GetTransaction(context.Background(), txid)
	if err != nil {
		return -1, nil, err
	}

	tx, err := transaction.NewTxFromHex(txhex)
	if err != nil {
		return -1, nil, err
	}

	inputValue, err := elementsutil.ValueFromBytes(tx.Outputs[index].Value)
	if err != nil {
		return -1, nil, err
	}

	sweepInput = &sweepLiquidInput{
		inputArgs: psetv2.InputArgs{
			Txid:    txid,
			TxIndex: index,
		},
		sweepLeaf: sweepLeaf,
		amount:    inputValue,
	}

	return lifetime, sweepInput, nil
}

func (b *txBuilder) VerifyTapscriptPartialSigs(tx string) (bool, string, error) {
	ptx, _ := psetv2.NewPsetFromBase64(tx)
	utx, _ := ptx.UnsignedTx()
	txid := utx.TxHash().String()

	for index, input := range ptx.Inputs {
		if len(input.TapLeafScript) == 0 {
			continue
		}
		if input.WitnessUtxo == nil {
			return false, txid, fmt.Errorf("missing witness utxo for input %d, cannot verify signature", index)
		}

		// verify taproot leaf script
		tapLeaf := input.TapLeafScript[0]

		rootHash := tapLeaf.ControlBlock.RootHash(tapLeaf.Script)
		tapKeyFromControlBlock := taproot.ComputeTaprootOutputKey(tree.UnspendableKey(), rootHash[:])

		pkscript, err := common.P2TRScript(tapKeyFromControlBlock)
		if err != nil {
			return false, txid, err
		}

		if !bytes.Equal(pkscript, input.WitnessUtxo.Script) {
			return false, txid, fmt.Errorf("invalid control block for input %d", index)
		}

		leafHash := taproot.NewBaseTapElementsLeaf(tapLeaf.Script).TapHash()

		preimage, err := b.getTaprootPreimage(
			tx,
			index,
			&leafHash,
		)
		if err != nil {
			return false, txid, err
		}

		for _, tapScriptSig := range input.TapScriptSig {
			sig, err := schnorr.ParseSignature(tapScriptSig.Signature)
			if err != nil {
				return false, txid, err
			}

			pubkey, err := schnorr.ParsePubKey(tapScriptSig.PubKey)
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
	p, err := psetv2.NewPsetFromBase64(tx)
	if err != nil {
		return "", err
	}

	if err := psetv2.FinalizeAll(p); err != nil {
		return "", err
	}

	// extract the forfeit tx
	extracted, err := psetv2.Extract(p)
	if err != nil {
		return "", err
	}

	return extracted.ToHex()
}

func (b *txBuilder) FindLeaves(
	congestionTree tree.CongestionTree,
	fromtxid string,
	fromvout uint32,
) ([]tree.Node, error) {
	allLeaves := congestionTree.Leaves()
	foundLeaves := make([]tree.Node, 0)

	for _, leaf := range allLeaves {
		branch, err := congestionTree.Branch(leaf.Txid)
		if err != nil {
			return nil, err
		}

		for _, node := range branch {
			ptx, err := psetv2.NewPsetFromBase64(node.Tx)
			if err != nil {
				return nil, err
			}

			if len(ptx.Inputs) <= 0 {
				return nil, fmt.Errorf("no input in the pset")
			}

			parentInput := ptx.Inputs[0]

			hash, err := chainhash.NewHash(parentInput.PreviousTxid)
			if err != nil {
				return nil, err
			}

			if hash.String() == fromtxid && parentInput.PreviousTxIndex == fromvout {
				foundLeaves = append(foundLeaves, leaf)
				break
			}
		}
	}

	return foundLeaves, nil
}

func (b *txBuilder) BuildAsyncPaymentTransactions(
	_ []domain.Vtxo, _ *secp256k1.PublicKey, _ []domain.Receiver,
) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (b *txBuilder) createPoolTx(
	sharedOutputAmount uint64,
	sharedOutputScript []byte,
	payments []domain.Payment,
	boardingInputs []ports.BoardingInput,
	aspPubKey *secp256k1.PublicKey,
	connectorAddress string,
	sweptRounds []domain.Round,
) (*psetv2.Pset, error) {
	aspScript, err := p2wpkhScript(aspPubKey, b.onchainNetwork())
	if err != nil {
		return nil, err
	}

	connectorScript, err := address.ToOutputScript(connectorAddress)
	if err != nil {
		return nil, err
	}

	connectorMinRelayFee, err := b.minRelayFeeConnectorTx()
	if err != nil {
		return nil, err
	}

	dustAmount, err := b.wallet.GetDustAmount(context.Background())
	if err != nil {
		return nil, err
	}

	receivers := getOnchainReceivers(payments)
	nbOfInputs := countSpentVtxos(payments)
	connectorsAmount := (dustAmount + connectorMinRelayFee) * nbOfInputs
	if nbOfInputs > 1 {
		connectorsAmount -= connectorMinRelayFee
	}
	targetAmount := connectorsAmount

	outputs := make([]psetv2.OutputArgs, 0)

	if sharedOutputScript != nil && sharedOutputAmount > 0 {
		targetAmount += sharedOutputAmount

		outputs = append(outputs, psetv2.OutputArgs{
			Asset:  b.onchainNetwork().AssetID,
			Amount: sharedOutputAmount,
			Script: sharedOutputScript,
		})
	}

	if connectorsAmount > 0 {
		outputs = append(outputs, psetv2.OutputArgs{
			Asset:  b.onchainNetwork().AssetID,
			Amount: connectorsAmount,
			Script: connectorScript,
		})
	}

	for _, receiver := range receivers {
		targetAmount += receiver.Amount

		receiverScript, err := address.ToOutputScript(receiver.OnchainAddress)
		if err != nil {
			return nil, err
		}

		outputs = append(outputs, psetv2.OutputArgs{
			Asset:  b.onchainNetwork().AssetID,
			Amount: receiver.Amount,
			Script: receiverScript,
		})
	}

	for _, in := range boardingInputs {
		targetAmount -= in.Amount
	}
	ctx := context.Background()

	dustLimit, err := b.wallet.GetDustAmount(ctx)
	if err != nil {
		return nil, err
	}

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
			outputs = append(outputs, psetv2.OutputArgs{
				Asset:  b.onchainNetwork().AssetID,
				Amount: change,
				Script: aspScript,
			})
		}
	}

	ptx, err := psetv2.New(nil, outputs, nil)
	if err != nil {
		return nil, err
	}

	updater, err := psetv2.NewUpdater(ptx)
	if err != nil {
		return nil, err
	}

	for _, in := range boardingInputs {
		if err := updater.AddInputs(
			[]psetv2.InputArgs{
				{
					Txid:    in.Txid,
					TxIndex: in.VtxoKey.VOut,
				},
			},
		); err != nil {
			return nil, err
		}

		index := len(ptx.Inputs) - 1

		assetBytes, err := elementsutil.AssetHashToBytes(b.onchainNetwork().AssetID)
		if err != nil {
			return nil, fmt.Errorf("failed to convert asset to bytes: %s", err)
		}

		valueBytes, err := elementsutil.ValueToBytes(in.Amount)
		if err != nil {
			return nil, fmt.Errorf("failed to convert value to bytes: %s", err)
		}

		boardingVtxoScript, err := tree.ParseVtxoScript(in.Descriptor)
		if err != nil {
			return nil, err
		}

		boardingTapKey, _, err := boardingVtxoScript.TapTree()
		if err != nil {
			return nil, err
		}

		boardingOutputScript, err := common.P2TRScript(boardingTapKey)
		if err != nil {
			return nil, err
		}

		if err := updater.AddInWitnessUtxo(index, transaction.NewTxOutput(assetBytes, valueBytes, boardingOutputScript)); err != nil {
			return nil, err
		}

		if err := updater.AddInSighashType(index, txscript.SigHashDefault); err != nil {
			return nil, err
		}
	}

	if err := addInputs(updater, utxos); err != nil {
		return nil, err
	}

	b64, err := ptx.ToBase64()
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
			ptx.Outputs = ptx.Outputs[:len(ptx.Outputs)-1]
			ptx.Global.OutputCount--
			feeAmount += change
		} else if feeAmount < change {
			// change covers the fees, reduce change amount
			if change-feeAmount < dustLimit {
				ptx.Outputs = ptx.Outputs[:len(ptx.Outputs)-1]
				ptx.Global.OutputCount--
				feeAmount += change
			} else {
				ptx.Outputs[len(ptx.Outputs)-1].Value = change - feeAmount
			}
		} else {
			// change is not enough to cover fees, re-select utxos
			if change > 0 {
				// remove change output if present
				ptx.Outputs = ptx.Outputs[:len(ptx.Outputs)-1]
				ptx.Global.OutputCount--
			}
			newUtxos, change, err := b.selectUtxos(ctx, sweptRounds, feeAmount-change)
			if err != nil {
				return nil, err
			}

			if change > 0 {
				if change < dustLimit {
					feeAmount += change
				} else {
					if err := updater.AddOutputs([]psetv2.OutputArgs{
						{
							Asset:  b.onchainNetwork().AssetID,
							Amount: change,
							Script: aspScript,
						},
					}); err != nil {
						return nil, err
					}
				}
			}

			if err := addInputs(updater, newUtxos); err != nil {
				return nil, err
			}
		}
	} else if feeAmount-dust > 0 {
		newUtxos, change, err := b.selectUtxos(ctx, sweptRounds, feeAmount-dust)
		if err != nil {
			return nil, err
		}

		if change > 0 {
			if change < dustLimit {
				feeAmount += change
			} else {
				if err := updater.AddOutputs([]psetv2.OutputArgs{
					{
						Asset:  b.onchainNetwork().AssetID,
						Amount: change,
						Script: aspScript,
					},
				}); err != nil {
					return nil, err
				}
			}
		}

		if err := addInputs(updater, newUtxos); err != nil {
			return nil, err
		}
	}

	// add fee output
	if err := updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  b.onchainNetwork().AssetID,
			Amount: feeAmount,
		},
	}); err != nil {
		return nil, err
	}

	return ptx, nil
}

func (b *txBuilder) minRelayFeeConnectorTx() (uint64, error) {
	return b.wallet.MinRelayFee(context.Background(), uint64(common.ConnectorTxSize))
}

// This method aims to verify and add partial signature from boarding input
func (b *txBuilder) VerifyAndCombinePartialTx(dest string, src string) (string, error) {
	roundPset, err := psetv2.NewPsetFromBase64(dest)
	if err != nil {
		return "", err
	}

	sourcePset, err := psetv2.NewPsetFromBase64(src)
	if err != nil {
		return "", err
	}

	roundUtx, err := roundPset.UnsignedTx()
	if err != nil {
		return "", err
	}

	sourceUtx, err := sourcePset.UnsignedTx()
	if err != nil {
		return "", err
	}

	if roundUtx.TxHash().String() != sourceUtx.TxHash().String() {
		return "", fmt.Errorf("txid mismatch")
	}

	roundSigner, err := psetv2.NewSigner(roundPset)
	if err != nil {
		return "", err
	}

	for i, input := range sourcePset.Inputs {
		if len(input.TapScriptSig) == 0 || len(input.TapLeafScript) == 0 {
			continue
		}

		partialSig := input.TapScriptSig[0]

		leafHash, err := chainhash.NewHash(partialSig.LeafHash)
		if err != nil {
			return "", err
		}

		preimage, err := b.getTaprootPreimage(src, i, leafHash)
		if err != nil {
			return "", err
		}

		sig, err := schnorr.ParseSignature(partialSig.Signature)
		if err != nil {
			return "", err
		}

		pubkey, err := schnorr.ParsePubKey(partialSig.PubKey)
		if err != nil {
			return "", err
		}

		if !sig.Verify(preimage, pubkey) {
			return "", fmt.Errorf("invalid signature")
		}

		if err := roundSigner.AddInTapLeafScript(i, input.TapLeafScript[0]); err != nil {
			return "", err
		}

		if err := roundSigner.SignTaprootInputTapscriptSig(i, partialSig); err != nil {
			return "", err
		}
	}

	return roundSigner.Pset.ToBase64()
}

func (b *txBuilder) createConnectors(
	poolTx string, payments []domain.Payment,
	connectorAddress string,
	connectorAmount, feeAmount uint64,
) ([]*psetv2.Pset, error) {
	txid, _ := getTxid(poolTx)

	aspScript, err := address.ToOutputScript(connectorAddress)
	if err != nil {
		return nil, err
	}

	connectorOutput := psetv2.OutputArgs{
		Asset:  b.onchainNetwork().AssetID,
		Script: aspScript,
		Amount: connectorAmount,
	}

	numberOfConnectors := countSpentVtxos(payments)

	previousInput := psetv2.InputArgs{
		Txid:    txid,
		TxIndex: 1,
	}

	if numberOfConnectors == 1 {
		outputs := []psetv2.OutputArgs{connectorOutput}
		connectorTx, err := craftConnectorTx(previousInput, aspScript, outputs, feeAmount)
		if err != nil {
			return nil, err
		}

		return []*psetv2.Pset{connectorTx}, nil
	}

	totalConnectorAmount := (connectorAmount + feeAmount) * numberOfConnectors
	if numberOfConnectors > 1 {
		totalConnectorAmount -= feeAmount
	}

	connectors := make([]*psetv2.Pset, 0, numberOfConnectors-1)
	for i := uint64(0); i < numberOfConnectors-1; i++ {
		outputs := []psetv2.OutputArgs{connectorOutput}
		totalConnectorAmount -= connectorAmount
		totalConnectorAmount -= feeAmount
		if totalConnectorAmount > 0 {
			outputs = append(outputs, psetv2.OutputArgs{
				Asset:  b.onchainNetwork().AssetID,
				Script: aspScript,
				Amount: totalConnectorAmount,
			})
		}
		connectorTx, err := craftConnectorTx(previousInput, aspScript, outputs, feeAmount)
		if err != nil {
			return nil, err
		}

		txid, err := getPsetId(connectorTx)
		if err != nil {
			return nil, err
		}

		previousInput = psetv2.InputArgs{
			Txid:    txid,
			TxIndex: 1,
		}

		connectors = append(connectors, connectorTx)
	}

	return connectors, nil
}

func (b *txBuilder) createForfeitTxs(
	payments []domain.Payment,
	connectors []*psetv2.Pset,
	connectorAmount uint64,
	minRelayFeeRate chainfee.SatPerKVByte,
) ([]string, error) {
	forfeitAddr, err := b.wallet.GetForfeitAddress(context.Background())
	if err != nil {
		return nil, err
	}

	forfeitPkScript, err := address.ToOutputScript(forfeitAddr)
	if err != nil {
		return nil, err
	}

	forfeitTxs := make([]string, 0)
	for _, payment := range payments {
		for _, vtxo := range payment.Inputs {
			offchainScript, err := tree.ParseVtxoScript(vtxo.Descriptor)
			if err != nil {
				return nil, err
			}

			vtxoTapKey, vtxoTree, err := offchainScript.TapTree()
			if err != nil {
				return nil, err
			}

			vtxoScript, err := common.P2TRScript(vtxoTapKey)
			if err != nil {
				return nil, err
			}

			feeAmount, err := common.ComputeForfeitMinRelayFee(minRelayFeeRate, vtxoTree, txscript.WitnessV0PubKeyHashTy)
			if err != nil {
				return nil, err
			}

			for _, connector := range connectors {
				txs, err := tree.BuildForfeitTxs(
					connector,
					psetv2.InputArgs{
						Txid:    vtxo.Txid,
						TxIndex: vtxo.VOut,
					},
					vtxo.Amount,
					connectorAmount,
					feeAmount,
					vtxoScript,
					forfeitPkScript,
				)
				if err != nil {
					return nil, err
				}

				for _, tx := range txs {
					b64, err := tx.ToBase64()
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

func (b *txBuilder) getConnectorAddress(poolTx string) (string, error) {
	pset, err := psetv2.NewPsetFromBase64(poolTx)
	if err != nil {
		return "", err
	}

	if len(pset.Outputs) < 1 {
		return "", fmt.Errorf("connector output not found in pool tx")
	}

	connectorOutput := pset.Outputs[1]

	pay, err := payment.FromScript(connectorOutput.Script, b.onchainNetwork(), nil)
	if err != nil {
		return "", err
	}

	return pay.WitnessPubKeyHash()
}

func (b *txBuilder) getTaprootPreimage(tx string, inputIndex int, leafHash *chainhash.Hash) ([]byte, error) {
	pset, err := psetv2.NewPsetFromBase64(tx)
	if err != nil {
		return nil, err
	}

	prevoutScripts := make([][]byte, 0)
	prevoutAssets := make([][]byte, 0)
	prevoutValues := make([][]byte, 0)

	for i, input := range pset.Inputs {
		if input.WitnessUtxo == nil {
			return nil, fmt.Errorf("missing witness utxo on input #%d", i)
		}

		prevoutScripts = append(prevoutScripts, input.WitnessUtxo.Script)
		prevoutAssets = append(prevoutAssets, input.WitnessUtxo.Asset)
		prevoutValues = append(prevoutValues, input.WitnessUtxo.Value)
	}

	utx, err := pset.UnsignedTx()
	if err != nil {
		return nil, err
	}

	genesisHash, _ := chainhash.NewHashFromStr(b.onchainNetwork().GenesisBlockHash)

	preimage := utx.HashForWitnessV1(
		inputIndex, prevoutScripts, prevoutAssets, prevoutValues,
		pset.Inputs[inputIndex].SigHashType, genesisHash, leafHash, nil,
	)
	return preimage[:], nil
}

func (b *txBuilder) onchainNetwork() *network.Network {
	switch b.net.Name {
	case common.Liquid.Name:
		return &network.Liquid
	case common.LiquidTestNet.Name:
		return &network.Testnet
	case common.LiquidRegTest.Name:
		return &network.Regtest
	default:
		return &network.Liquid
	}
}

func extractSweepLeaf(input psetv2.Input) (sweepLeaf *psetv2.TapLeafScript, lifetime int64, err error) {
	for _, leaf := range input.TapLeafScript {
		closure := &tree.CSVSigClosure{}
		valid, err := closure.Decode(leaf.Script)
		if err != nil {
			return nil, 0, err
		}
		if valid && closure.Seconds > uint(lifetime) {
			sweepLeaf = &leaf
			lifetime = int64(closure.Seconds)
		}
	}

	if sweepLeaf == nil {
		return nil, 0, fmt.Errorf("sweep leaf not found")
	}

	return sweepLeaf, lifetime, nil
}

type sweepLiquidInput struct {
	inputArgs psetv2.InputArgs
	sweepLeaf *psetv2.TapLeafScript
	amount    uint64
}

func (s *sweepLiquidInput) GetAmount() uint64 {
	return s.amount
}

func (s *sweepLiquidInput) GetControlBlock() []byte {
	ctrlBlock, _ := s.sweepLeaf.ControlBlock.ToBytes()
	return ctrlBlock
}

func (s *sweepLiquidInput) GetHash() chainhash.Hash {
	h, _ := chainhash.NewHashFromStr(s.inputArgs.Txid)
	return *h
}

func (s *sweepLiquidInput) GetIndex() uint32 {
	return s.inputArgs.TxIndex
}

func (s *sweepLiquidInput) GetInternalKey() *secp256k1.PublicKey {
	return s.sweepLeaf.ControlBlock.InternalKey
}

func (s *sweepLiquidInput) GetLeafScript() []byte {
	return s.sweepLeaf.Script
}
