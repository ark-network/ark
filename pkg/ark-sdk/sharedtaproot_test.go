package sdk_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	sdk "github.com/ark-network/ark-sdk"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
	"github.com/vulpemventures/go-elements/transaction"
)

func TestSharedOutput(t *testing.T) {
	alice, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	bob, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	eve, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	alicePayment := payment.FromPublicKey(alice.PubKey(), &network.Regtest, nil)
	aliceAddress, err := alicePayment.WitnessPubKeyHash()
	require.NoError(t, err)
	bobPayment := payment.FromPublicKey(bob.PubKey(), &network.Regtest, nil)
	bobAddress, err := bobPayment.WitnessPubKeyHash()
	require.NoError(t, err)

	evePayment := payment.FromPublicKey(eve.PubKey(), &network.Regtest, nil)
	eveAddress, err := evePayment.WitnessPubKeyHash()
	require.NoError(t, err)

	_, err = faucet(aliceAddress)
	require.NoError(t, err)
	_, err = faucet(bobAddress)
	require.NoError(t, err)
	_, err = faucet(eveAddress)
	require.NoError(t, err)

	aliceUtxos, err := unspents(aliceAddress)
	require.NoError(t, err)
	bobUtxos, err := unspents(bobAddress)
	require.NoError(t, err)
	eveUtxos, err := unspents(eveAddress)
	require.NoError(t, err)

	aliceUtxo := aliceUtxos[0]
	bobUtxo := bobUtxos[0]
	eveUtxo := eveUtxos[0]

	aliceSharedAmount := uint32(10_000)
	aliceChangeAmount := uint32(1_0000_0000 - aliceSharedAmount - 500)
	bobSharedAmount := uint32(100_000)
	bobChangeAmount := uint32(1_0000_0000 - bobSharedAmount)
	eveSharedAmount := uint32(1_0000_0000)

	aliceInput := psetv2.InputArgs{
		Txid:    aliceUtxo["txid"].(string),
		TxIndex: uint32(aliceUtxo["vout"].(float64)),
	}
	aliceInputWitnessUtxo, err := witnessUtxo(aliceInput.Txid, aliceInput.TxIndex)
	require.NoError(t, err)

	bobInput := psetv2.InputArgs{
		Txid:    bobUtxo["txid"].(string),
		TxIndex: uint32(bobUtxo["vout"].(float64)),
	}
	bobInputWitnessUtxo, err := witnessUtxo(bobInput.Txid, bobInput.TxIndex)
	require.NoError(t, err)

	eveInput := psetv2.InputArgs{
		Txid:    eveUtxo["txid"].(string),
		TxIndex: uint32(eveUtxo["vout"].(float64)),
	}
	eveInputWitnessUtxo, err := witnessUtxo(eveInput.Txid, eveInput.TxIndex)
	require.NoError(t, err)

	aliceOutput := psetv2.OutputArgs{
		Asset:  network.Regtest.AssetID,
		Amount: uint64(aliceChangeAmount),
		Script: alicePayment.Script,
	}

	bobOutput := psetv2.OutputArgs{
		Asset:  network.Regtest.AssetID,
		Amount: uint64(bobChangeAmount),
		Script: bobPayment.Script,
	}

	aliceStakeHolder := sdk.Stakeholder{
		Leaves: []taproot.TapElementsLeaf{
			checksigTapscript(alice.PubKey()),
		},
		Amount: aliceSharedAmount,
	}

	bobStakeHolder := sdk.Stakeholder{
		Leaves: []taproot.TapElementsLeaf{
			checksigTapscript(bob.PubKey()),
		},
		Amount: bobSharedAmount,
	}

	eveStakeHolder := sdk.Stakeholder{
		Leaves: []taproot.TapElementsLeaf{
			checksigTapscript(eve.PubKey()),
		},
		Amount: eveSharedAmount,
	}

	sharedTaprootTree, err := sdk.NewSharedTaprootScript(
		[]sdk.Stakeholder{
			aliceStakeHolder,
			bobStakeHolder,
			eveStakeHolder,
		},
		[]taproot.TapElementsLeaf{},
		alice.PubKey(),
	)
	require.NoError(t, err)

	sharedOutput := psetv2.OutputArgs{
		Asset:  network.Regtest.AssetID,
		Amount: uint64(aliceSharedAmount + bobSharedAmount + eveSharedAmount),
		Script: sharedTaprootTree.ScriptPubKey(),
	}

	feeOutput := psetv2.OutputArgs{
		Asset:  network.Regtest.AssetID,
		Amount: uint64(500),
	}

	pset, err := psetv2.New(
		[]psetv2.InputArgs{aliceInput, bobInput, eveInput},
		[]psetv2.OutputArgs{aliceOutput, bobOutput, sharedOutput, feeOutput},
		nil,
	)
	require.NoError(t, err)

	// set the witnessUtxos
	updater0, err := psetv2.NewUpdater(pset)
	require.NoError(t, err)

	err = updater0.AddInWitnessUtxo(0, aliceInputWitnessUtxo)
	require.NoError(t, err)

	err = updater0.AddInWitnessUtxo(1, bobInputWitnessUtxo)
	require.NoError(t, err)

	err = updater0.AddInWitnessUtxo(2, eveInputWitnessUtxo)
	require.NoError(t, err)

	// Sign the transaction.
	err = signTransaction(
		pset,
		[]*btcec.PrivateKey{alice, bob, eve},
		[][]byte{alicePayment.Script, bobPayment.Script, evePayment.Script},
		true,
		nil,
	)
	require.NoError(t, err)

	tx0, err := broadcastTransaction(pset)
	require.NoError(t, err)

	// Alice wants to exit the shared covenant

	aliceInput = psetv2.InputArgs{
		Txid:    tx0,
		TxIndex: 2,
	}
	aliceInputWitnessUtxo, err = witnessUtxo(aliceInput.Txid, aliceInput.TxIndex)
	require.NoError(t, err)

	aliceChangeRequirements, tapLeafProof, err := sharedTaprootTree.Requirements(aliceStakeHolder.Leaves[0].Script)
	require.NoError(t, err)
	require.NotNil(t, aliceChangeRequirements)

	aliceChangeOutput := psetv2.OutputArgs{
		Asset:  network.Regtest.AssetID,
		Amount: uint64(aliceChangeRequirements.Amount),
		Script: aliceChangeRequirements.ScriptPubKey,
	}

	alicePayoutOutput := psetv2.OutputArgs{
		Asset:  network.Regtest.AssetID,
		Amount: uint64(aliceSharedAmount - 500),
		Script: alicePayment.Script,
	}

	pset, err = psetv2.New(
		[]psetv2.InputArgs{aliceInput},
		[]psetv2.OutputArgs{aliceChangeOutput, alicePayoutOutput, feeOutput},
		nil,
	)
	require.NoError(t, err)

	updater1, err := psetv2.NewUpdater(pset)
	require.NoError(t, err)

	err = updater1.AddInWitnessUtxo(0, aliceInputWitnessUtxo)
	require.NoError(t, err)

	signed, err := signChecksigTapscript(pset, alice, tapLeafProof, alice.PubKey())
	require.NoError(t, err)

	hex, err := signed.ToHex()
	require.NoError(t, err)

	log.Print(hex)
	tx1, err := broadcast(hex)
	require.NoError(t, err)

	require.NotNil(t, tx1)
}

func signChecksigTapscript(
	pset *psetv2.Pset,
	privKey *btcec.PrivateKey,
	tapLeafProof *taproot.TapscriptElementsProof,
	internalPubKey *btcec.PublicKey,
) (*transaction.Transaction, error) {
	tx, err := pset.UnsignedTx()
	if err != nil {
		return nil, err
	}

	genesisBlockhash, _ := chainhash.NewHashFromStr("00902a6b70c2ca83b5d9c815d96a0e2f4202179316970d14ea1847dae5b1ca21")
	leafHash := tapLeafProof.TapHash()

	prevoutScripts := make([][]byte, len(tx.Inputs))
	prevoutValues := make([][]byte, len(tx.Inputs))
	prevoutAssets := make([][]byte, len(tx.Inputs))

	for i, in := range pset.Inputs {
		prevoutScripts[i] = in.WitnessUtxo.Script
		prevoutAssets[i] = in.WitnessUtxo.Asset
		prevoutValues[i] = in.WitnessUtxo.Value
	}

	preimage := tx.HashForWitnessV1(
		0,
		prevoutScripts,
		prevoutAssets,
		prevoutValues,
		txscript.SigHashDefault,
		genesisBlockhash,
		&leafHash,
		nil,
	)

	sig, err := schnorr.Sign(privKey, preimage[:])
	if err != nil {
		return nil, err
	}

	controlBlock := tapLeafProof.ToControlBlock(internalPubKey)
	controlBlockBytes, err := controlBlock.ToBytes()
	if err != nil {
		return nil, err
	}

	tx.Inputs[0].Witness = transaction.TxWitness{
		sig.Serialize(),
		tapLeafProof.Script,
		controlBlockBytes,
	}

	return tx, nil
}

func checksigTapscript(pubKey *btcec.PublicKey) taproot.TapElementsLeaf {
	script := []byte{txscript.OP_DATA_32}
	script = append(script, schnorr.SerializePubKey(pubKey)...)
	script = append(script, byte(txscript.OP_CHECKSIG))
	return taproot.NewBaseTapElementsLeaf(script)
}

type signOpts struct {
	pubkeyScript []byte
	script       []byte
}

func signTransaction(
	p *psetv2.Pset,
	privKeys []*btcec.PrivateKey,
	scripts [][]byte,
	forWitness bool,
	opts *signOpts,
) error {
	updater, err := psetv2.NewUpdater(p)
	if err != nil {
		return err
	}

	unsignedTx, err := p.UnsignedTx()
	if err != nil {
		return err
	}

	for i, in := range p.Inputs {
		if err := updater.AddInSighashType(i, txscript.SigHashAll); err != nil {
			return err
		}

		var prevout *transaction.TxOutput
		if in.WitnessUtxo != nil {
			prevout = in.WitnessUtxo
		} else {
			prevout = in.NonWitnessUtxo.Outputs[unsignedTx.Inputs[i].Index]
		}
		prvkey := privKeys[i]
		pubkey := prvkey.PubKey()
		script := scripts[i]

		var sigHash [32]byte
		if forWitness {
			sigHash = unsignedTx.HashForWitnessV0(
				i,
				script,
				prevout.Value,
				txscript.SigHashAll,
			)
		} else {
			sigHash, err = unsignedTx.HashForSignature(i, script, txscript.SigHashAll)
			if err != nil {
				return err
			}
		}

		sig := ecdsa.Sign(prvkey, sigHash[:])
		sigWithHashType := append(sig.Serialize(), byte(txscript.SigHashAll))

		var witPubkeyScript []byte
		var witScript []byte
		if opts != nil {
			witPubkeyScript = opts.pubkeyScript
			witScript = opts.script
		}

		signer, err := psetv2.NewSigner(p)
		if err != nil {
			return err
		}

		if err = signer.SignInput(
			i,
			sigWithHashType,
			pubkey.SerializeCompressed(),
			witPubkeyScript,
			witScript,
		); err != nil {
			return err
		}

		valid, err := p.ValidateInputSignatures(i)
		if err != nil {
			return err
		}

		if !valid {
			return errors.New("invalid signature for input " + fmt.Sprint(i))
		}
	}

	return nil
}

func broadcast(txHex string) (string, error) {
	baseUrl, err := apiBaseUrl()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/tx", baseUrl)

	resp, err := http.Post(url, "text/plain", strings.NewReader(txHex))
	if err != nil {
		return "", err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	res := string(data)
	if len(res) <= 0 || strings.Contains(res, "sendrawtransaction") {
		return "", fmt.Errorf("failed to broadcast tx: %s", res)
	}
	return res, nil
}

func broadcastTransaction(p *psetv2.Pset) (string, error) {
	// Finalize the partial transaction.
	if err := psetv2.FinalizeAll(p); err != nil {
		return "", err
	}
	// Extract the final signed transaction from the Pset wrapper.
	finalTx, err := psetv2.Extract(p)
	if err != nil {
		return "", err
	}
	// Serialize the transaction and try to broadcast.
	txHex, err := finalTx.ToHex()
	if err != nil {
		return "", err
	}

	return broadcast(txHex)
}

func apiBaseUrl() (string, error) {
	u, ok := os.LookupEnv("API_URL")
	if !ok {
		return "", errors.New("API_URL environment variable is not set")
	}
	return u, nil
}

func witnessUtxo(txID string, vout uint32) (*transaction.TxOutput, error) {
	txHex, err := fetchTx(txID)
	if err != nil {
		return nil, err
	}

	tx, err := transaction.NewTxFromHex(txHex)
	if err != nil {
		return nil, err
	}

	return tx.Outputs[vout], nil
}

func fetchTx(txId string) (string, error) {
	baseUrl, err := apiBaseUrl()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/tx/%s/hex", baseUrl, txId)

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func unspents(address string) ([]map[string]interface{}, error) {
	getUtxos := func(address string) ([]interface{}, error) {
		baseUrl, err := apiBaseUrl()
		if err != nil {
			return nil, err
		}
		url := fmt.Sprintf("%s/address/%s/utxo", baseUrl, address)
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var respBody interface{}
		if err := json.Unmarshal(data, &respBody); err != nil {
			return nil, err
		}
		return respBody.([]interface{}), nil
	}

	utxos := []map[string]interface{}{}
	for len(utxos) <= 0 {
		time.Sleep(1 * time.Second)
		u, err := getUtxos(address)
		if err != nil {
			return nil, err
		}
		for _, unspent := range u {
			utxo := unspent.(map[string]interface{})
			utxos = append(utxos, utxo)
		}
	}

	return utxos, nil
}

func faucet(address string) (string, error) {
	baseUrl, err := apiBaseUrl()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/faucet", baseUrl)
	payload := map[string]string{"address": address}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if res := string(data); len(res) <= 0 || strings.Contains(res, "sendtoaddress") {
		return "", fmt.Errorf("cannot fund address with faucet: %s", res)
	}

	respBody := map[string]string{}
	if err := json.Unmarshal(data, &respBody); err != nil {
		return "", err
	}
	return respBody["txId"], nil
}
