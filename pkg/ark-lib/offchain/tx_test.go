package offchain

import (
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

func TestBuildArkTxRejectsMixedLocktimeTypes(t *testing.T) {
	newInput := func(locktime arklib.AbsoluteLocktime, index uint32) VtxoInput {
		closure := &script.CLTVMultisigClosure{
			Locktime: locktime,
			MultisigClosure: script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{script.UnspendableKey()},
			},
		}
		revealedScript, err := closure.Script()
		require.NoError(t, err)

		return VtxoInput{
			Outpoint: &wire.OutPoint{Index: index},
			Amount:   1_000,
			Tapscript: &waddrmgr.Tapscript{
				ControlBlock: &txscript.ControlBlock{
					InternalKey: script.UnspendableKey(),
					LeafVersion: txscript.BaseLeafVersion,
				},
				RevealedScript: revealedScript,
			},
			RevealedTapscripts: []string{hex.EncodeToString(revealedScript)},
		}
	}

	zero := newInput(0, 0)
	timestamp := newInput(1_700_000_000, 1)
	for _, test := range []struct {
		name   string
		inputs []VtxoInput
	}{
		{name: "zero first", inputs: []VtxoInput{zero, timestamp}},
		{name: "timestamp first", inputs: []VtxoInput{timestamp, zero}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := buildArkTx(test.inputs, nil)
			require.EqualError(t, err, "mixed absolute locktime types")
		})
	}
}

func TestValidateTxFee(t *testing.T) {
	for _, test := range []struct {
		name    string
		input   int64
		output  int64
		maxFee  int64
		wantErr bool
	}{
		{name: "balanced old operator", input: 616, output: 616, maxFee: 0},
		{name: "bounded fee", input: 616, output: 505, maxFee: 329},
		{name: "fee at cap", input: 829, output: 500, maxFee: 329},
		{name: "old operator rejects fee", input: 616, output: 505, maxFee: 0, wantErr: true},
		{name: "fee above cap", input: 830, output: 500, maxFee: 329, wantErr: true},
		{name: "overspend", input: 500, output: 501, maxFee: 329, wantErr: true},
		{name: "negative cap", input: 500, output: 500, maxFee: -1, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateTxFee(test.input, test.output, test.maxFee)
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestBuildTxsWithMaxFee(t *testing.T) {
	key := script.UnspendableKey()
	ownerScript, err := (&script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{key},
	}).Script()
	require.NoError(t, err)
	unrollScript, err := (&script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{key}},
		Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144},
	}).Script()
	require.NoError(t, err)

	input := VtxoInput{
		Outpoint: &wire.OutPoint{},
		Amount:   616,
		Tapscript: &waddrmgr.Tapscript{
			ControlBlock: &txscript.ControlBlock{
				InternalKey: key,
				LeafVersion: txscript.BaseLeafVersion,
			},
			RevealedScript: ownerScript,
		},
		RevealedTapscripts: []string{hex.EncodeToString(ownerScript)},
	}
	outputScript, err := script.P2TRScript(key)
	require.NoError(t, err)
	outputs := []*wire.TxOut{{Value: 505, PkScript: outputScript}}

	arkTx, checkpoints, err := BuildTxsWithMaxFee([]VtxoInput{input}, outputs, unrollScript, 329)
	require.NoError(t, err)
	require.Equal(t, int64(616), arkTx.Inputs[0].WitnessUtxo.Value)
	require.Equal(t, int64(505), arkTx.UnsignedTx.TxOut[0].Value)
	require.Equal(t, int64(616), checkpoints[0].UnsignedTx.TxOut[0].Value)

	_, _, err = BuildTxs([]VtxoInput{input}, outputs, unrollScript)
	require.Error(t, err)
}
