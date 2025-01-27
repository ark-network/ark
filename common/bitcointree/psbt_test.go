package bitcointree_test

import (
	"testing"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

func TestPsbtCustomUnknownFields(t *testing.T) {
	t.Run("condition witness", func(t *testing.T) {
		// Create a new PSBT
		ptx, err := psbt.New(nil, nil, 2, 0, nil)
		require.NoError(t, err)

		// Add an empty input since we need at least one
		ptx.UnsignedTx.TxIn = []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{},
			Sequence:         0,
		}}
		ptx.Inputs = []psbt.PInput{{}}

		// Create a sample witness
		witness := wire.TxWitness{
			[]byte{0x01, 0x02},
			[]byte{0x03, 0x04},
		}

		// Add witness to input 0
		err = bitcointree.AddConditionWitness(0, ptx, witness)
		require.NoError(t, err)

		// Get witness back and verify
		retrievedWitness, err := bitcointree.GetConditionWitness(ptx.Inputs[0])
		require.NoError(t, err)
		require.Equal(t, len(witness), len(retrievedWitness))

		for i := range witness {
			require.Equal(t, witness[i], retrievedWitness[i])
		}
	})

	t.Run("vtxo tree expiry", func(t *testing.T) {
		// Create a new PSBT
		ptx, err := psbt.New(nil, nil, 2, 0, nil)
		require.NoError(t, err)

		// Add an empty input
		ptx.UnsignedTx.TxIn = []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{},
			Sequence:         0,
		}}
		ptx.Inputs = []psbt.PInput{{}}

		// Add vtxo tree expiry
		vtxoTreeExpiry := common.RelativeLocktime{
			Type:  common.LocktimeTypeBlock,
			Value: 144, // 1 day worth of blocks
		}
		err = bitcointree.AddVtxoTreeExpiry(0, ptx, vtxoTreeExpiry)
		require.NoError(t, err)

		// Get vtxo tree expiry back and verify
		retrievedVtxoTreeExpiry, err := bitcointree.GetVtxoTreeExpiry(ptx.Inputs[0])
		require.NoError(t, err)
		require.NotNil(t, retrievedVtxoTreeExpiry)
		require.Equal(t, vtxoTreeExpiry.Type, retrievedVtxoTreeExpiry.Type)
		require.Equal(t, vtxoTreeExpiry.Value, retrievedVtxoTreeExpiry.Value)
	})

	t.Run("cosigner keys", func(t *testing.T) {
		// Create a new PSBT
		ptx, err := psbt.New(nil, nil, 2, 0, nil)
		require.NoError(t, err)

		// Add an empty input
		ptx.UnsignedTx.TxIn = []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{},
			Sequence:         0,
		}}
		ptx.Inputs = []psbt.PInput{{}}

		// Create and add 40 cosigner keys
		var keys []*secp256k1.PublicKey
		for i := 0; i < 40; i++ {
			key, err := secp256k1.GeneratePrivateKey()
			require.NoError(t, err)
			keys = append(keys, key.PubKey())

			err = bitcointree.AddCosignerKey(0, ptx, key.PubKey())
			require.NoError(t, err)
		}

		// Get cosigner keys back and verify
		retrievedKeys, err := bitcointree.GetCosignerKeys(ptx.Inputs[0])
		require.NoError(t, err)
		require.Len(t, retrievedKeys, 40)

		// Verify each key matches and is in the correct order
		for i := 0; i < 40; i++ {
			require.Equal(t, keys[i].SerializeCompressed(), retrievedKeys[i].SerializeCompressed())
		}
	})
}
