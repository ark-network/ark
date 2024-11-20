package tree_test

import (
	"encoding/hex"
	"testing"

	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

func TestRoundTripCSV(t *testing.T) {
	seckey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	csvSig := &tree.CSVSigClosure{
		MultisigClosure: tree.MultisigClosure{
			PubKeys: []*secp256k1.PublicKey{seckey.PubKey()},
		},
		Seconds: 1024,
	}

	leaf, err := csvSig.Script()
	require.NoError(t, err)

	var cl tree.CSVSigClosure

	valid, err := cl.Decode(leaf)
	require.NoError(t, err)
	require.True(t, valid)

	require.Equal(t, csvSig.Seconds, cl.Seconds)
}

func TestMultisigClosure(t *testing.T) {
	// Generate some test keys
	privKey1, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pubKey1 := privKey1.PubKey()

	privKey2, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pubKey2 := privKey2.PubKey()

	t.Run("valid 2-of-2 multisig", func(t *testing.T) {
		closure := &tree.MultisigClosure{
			PubKeys: []*secp256k1.PublicKey{pubKey1, pubKey2},
		}

		// Generate script
		script, err := closure.Script()
		require.NoError(t, err)

		// Test decoding
		decodedClosure := &tree.MultisigClosure{}
		valid, err := decodedClosure.Decode(script)
		require.NoError(t, err)
		require.True(t, valid)
		require.Equal(t, 2, len(decodedClosure.PubKeys))

		// Compare serialized pubkeys
		require.Equal(t,
			schnorr.SerializePubKey(pubKey1),
			schnorr.SerializePubKey(decodedClosure.PubKeys[0]),
		)
		require.Equal(t,
			schnorr.SerializePubKey(pubKey2),
			schnorr.SerializePubKey(decodedClosure.PubKeys[1]),
		)
	})

	t.Run("valid single key multisig", func(t *testing.T) {
		closure := &tree.MultisigClosure{
			PubKeys: []*secp256k1.PublicKey{pubKey1},
		}

		script, err := closure.Script()
		require.NoError(t, err)

		decodedClosure := &tree.MultisigClosure{}
		valid, err := decodedClosure.Decode(script)
		require.NoError(t, err)
		require.True(t, valid)
		require.Equal(t, 1, len(decodedClosure.PubKeys))

		// Compare serialized pubkey
		require.Equal(t,
			schnorr.SerializePubKey(pubKey1),
			schnorr.SerializePubKey(decodedClosure.PubKeys[0]),
		)
	})

	t.Run("invalid empty script", func(t *testing.T) {
		closure := &tree.MultisigClosure{}
		valid, err := closure.Decode([]byte{})
		require.Error(t, err)
		require.False(t, valid)
	})

	t.Run("invalid script - wrong data push", func(t *testing.T) {
		script := []byte{
			txscript.OP_DATA_33, // Wrong size for schnorr pubkey
		}
		closure := &tree.MultisigClosure{}
		valid, err := closure.Decode(script)
		require.NoError(t, err)
		require.False(t, valid)
	})

	t.Run("invalid script - missing checksig", func(t *testing.T) {
		pubKeyBytes := schnorr.SerializePubKey(pubKey1)
		script := []byte{txscript.OP_DATA_32}
		script = append(script, pubKeyBytes...)
		// Missing OP_CHECKSIG

		closure := &tree.MultisigClosure{}
		valid, err := closure.Decode(script)
		require.NoError(t, err)
		require.False(t, valid)
	})

	t.Run("invalid script - extra data after checksig", func(t *testing.T) {
		pubKeyBytes := schnorr.SerializePubKey(pubKey1)
		script := []byte{txscript.OP_DATA_32}
		script = append(script, pubKeyBytes...)
		script = append(script, txscript.OP_CHECKSIG)
		script = append(script, 0x00) // Extra unwanted byte

		closure := &tree.MultisigClosure{}
		valid, err := closure.Decode(script)
		require.NoError(t, err)
		require.False(t, valid)
	})

	t.Run("witness size", func(t *testing.T) {
		closure := &tree.MultisigClosure{
			PubKeys: []*secp256k1.PublicKey{pubKey1, pubKey2},
		}

		require.Equal(t, 128, closure.WitnessSize()) // 64 * 2 bytes
	})

	t.Run("valid 12-of-12 multisig", func(t *testing.T) {
		// Generate 12 keys
		pubKeys := make([]*secp256k1.PublicKey, 12)
		for i := 0; i < 12; i++ {
			privKey, err := secp256k1.GeneratePrivateKey()
			require.NoError(t, err)
			pubKeys[i] = privKey.PubKey()
		}

		closure := &tree.MultisigClosure{
			PubKeys: pubKeys,
		}

		// Generate script
		script, err := closure.Script()
		require.NoError(t, err)

		// Test decoding
		decodedClosure := &tree.MultisigClosure{}
		valid, err := decodedClosure.Decode(script)
		require.NoError(t, err)
		require.True(t, valid)
		require.Equal(t, 12, len(decodedClosure.PubKeys))

		// Compare all serialized pubkeys
		for i := 0; i < 12; i++ {
			require.Equal(t,
				schnorr.SerializePubKey(pubKeys[i]),
				schnorr.SerializePubKey(decodedClosure.PubKeys[i]),
			)
		}

		// Verify witness size is correct for 12 signatures
		require.Equal(t, 64*12, closure.WitnessSize())
	})
}

func TestCSVSigClosure(t *testing.T) {
	// Generate test keys
	privKey1, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pubKey1 := privKey1.PubKey()

	privKey2, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pubKey2 := privKey2.PubKey()

	t.Run("valid single key CSV", func(t *testing.T) {
		csvSig := &tree.CSVSigClosure{
			MultisigClosure: tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pubKey1},
			},
			Seconds: 1024,
		}

		script, err := csvSig.Script()
		require.NoError(t, err)

		decodedCSV := &tree.CSVSigClosure{}
		valid, err := decodedCSV.Decode(script)
		require.NoError(t, err)
		require.True(t, valid)
		require.Equal(t, uint32(1024), uint32(decodedCSV.Seconds))
		require.Equal(t, 1, len(decodedCSV.PubKeys))
		require.Equal(t,
			schnorr.SerializePubKey(pubKey1),
			schnorr.SerializePubKey(decodedCSV.PubKeys[0]),
		)
	})

	t.Run("valid 2-of-2 CSV", func(t *testing.T) {
		csvSig := &tree.CSVSigClosure{
			MultisigClosure: tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pubKey1, pubKey2},
			},
			Seconds: 2016, // ~2 weeks
		}

		script, err := csvSig.Script()
		require.NoError(t, err)

		decodedCSV := &tree.CSVSigClosure{}
		valid, err := decodedCSV.Decode(script)
		require.NoError(t, err)
		require.True(t, valid)
		require.Equal(t, uint32(2016), uint32(decodedCSV.Seconds))
		require.Equal(t, 2, len(decodedCSV.PubKeys))
		require.Equal(t,
			schnorr.SerializePubKey(pubKey1),
			schnorr.SerializePubKey(decodedCSV.PubKeys[0]),
		)
		require.Equal(t,
			schnorr.SerializePubKey(pubKey2),
			schnorr.SerializePubKey(decodedCSV.PubKeys[1]),
		)
	})

	t.Run("invalid empty script", func(t *testing.T) {
		csvSig := &tree.CSVSigClosure{}
		valid, err := csvSig.Decode([]byte{})
		require.Error(t, err)
		require.False(t, valid)
	})

	t.Run("invalid CSV value", func(t *testing.T) {
		// Create a script with invalid CSV value
		pubKeyBytes := schnorr.SerializePubKey(pubKey1)
		script := []byte{txscript.OP_DATA_32}
		script = append(script, pubKeyBytes...)
		script = append(script, txscript.OP_CHECKSIG)
		script = append(script, 0xFF) // Invalid CSV value

		csvSig := &tree.CSVSigClosure{}
		valid, err := csvSig.Decode(script)
		require.NoError(t, err)
		require.False(t, valid)
	})

	t.Run("witness size", func(t *testing.T) {
		csvSig := &tree.CSVSigClosure{
			MultisigClosure: tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pubKey1, pubKey2},
			},
			Seconds: 1024,
		}
		// Should be same as multisig witness size (64 bytes per signature)
		require.Equal(t, 128, csvSig.WitnessSize())
	})

	t.Run("max timelock", func(t *testing.T) {
		csvSig := &tree.CSVSigClosure{
			MultisigClosure: tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pubKey1},
			},
			Seconds: 65535, // Maximum allowed value
		}

		script, err := csvSig.Script()
		require.NoError(t, err)

		decodedCSV := &tree.CSVSigClosure{}
		valid, err := decodedCSV.Decode(script)
		require.NoError(t, err)
		require.True(t, valid)
		require.Equal(t, uint32(65535), uint32(decodedCSV.Seconds))
	})
}

func TestMultisigClosureWitness(t *testing.T) {
	// Generate test keys
	priv1, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pub1 := priv1.PubKey()

	priv2, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pub2 := priv2.PubKey()

	// Mock control block
	controlBlock := []byte("control block")

	testCases := []struct {
		name        string
		closure     *tree.MultisigClosure
		signatures  map[string][]byte
		expectError bool
	}{
		{
			name: "single signature success",
			closure: &tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pub1},
			},
			signatures: map[string][]byte{
				hex.EncodeToString(schnorr.SerializePubKey(pub1)): []byte("signature1"),
			},
			expectError: false,
		},
		{
			name: "multiple signatures success",
			closure: &tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pub1, pub2},
			},
			signatures: map[string][]byte{
				hex.EncodeToString(schnorr.SerializePubKey(pub1)): []byte("signature1"),
				hex.EncodeToString(schnorr.SerializePubKey(pub2)): []byte("signature2"),
			},
			expectError: false,
		},
		{
			name: "missing signature",
			closure: &tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pub1, pub2},
			},
			signatures: map[string][]byte{
				hex.EncodeToString(schnorr.SerializePubKey(pub1)): []byte("signature1"),
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			witness, err := tc.closure.Witness(controlBlock, tc.signatures)
			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Total witness stack should be: signatures + script + control block
			expectedLen := len(tc.closure.PubKeys) + 2
			require.Equal(t, expectedLen, len(witness))

			// Verify signatures are in correct order (reverse order of pubkeys)
			for i := len(tc.closure.PubKeys) - 1; i >= 0; i-- {
				expectedSig := tc.signatures[hex.EncodeToString(schnorr.SerializePubKey(tc.closure.PubKeys[i]))]
				witnessIndex := len(witness) - 3 - i
				require.Equal(t, expectedSig, witness[:len(witness)-2][witnessIndex])
			}

			// Verify script is present
			script, err := tc.closure.Script()
			require.NoError(t, err)
			require.Equal(t, script, witness[len(witness)-2])

			// Verify control block is last
			require.Equal(t, controlBlock, witness[len(witness)-1])
		})
	}
}

func TestUnrollClosureWitness(t *testing.T) {
	closure := &tree.UnrollClosure{
		LeftKey:     secp256k1.NewPublicKey(new(secp256k1.FieldVal), new(secp256k1.FieldVal)),
		RightKey:    secp256k1.NewPublicKey(new(secp256k1.FieldVal), new(secp256k1.FieldVal)),
		LeftAmount:  1000,
		RightAmount: 2000,
	}

	controlBlock := []byte("control block")
	witness, err := closure.Witness(controlBlock, nil)
	require.NoError(t, err)

	// Should contain script and control block
	require.Equal(t, 2, len(witness))

	// Verify script is first
	script, err := closure.Script()
	require.NoError(t, err)
	require.Equal(t, script, witness[0])

	// Verify control block is last
	require.Equal(t, controlBlock, witness[1])
}

func TestCSVSigClosureWitness(t *testing.T) {
	// Generate test keys
	priv1, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pub1 := priv1.PubKey()

	// Create test signature
	testSig := []byte("signature1")
	signatures := map[string][]byte{
		hex.EncodeToString(schnorr.SerializePubKey(pub1)): testSig,
	}

	controlBlock := []byte("control block")

	closure := &tree.CSVSigClosure{
		MultisigClosure: tree.MultisigClosure{
			PubKeys: []*secp256k1.PublicKey{pub1},
		},
		Seconds: 144,
	}

	witness, err := closure.Witness(controlBlock, signatures)
	require.NoError(t, err)

	// Should contain: signature + script + control block
	require.Equal(t, 3, len(witness))
	require.Equal(t, testSig, witness[0])

	script, err := closure.Script()
	require.NoError(t, err)
	require.Equal(t, script, witness[1])
	require.Equal(t, controlBlock, witness[2])

	// Test missing signature
	_, err = closure.Witness(controlBlock, nil)
	require.Error(t, err)
}

func TestDecodeChecksigAdd(t *testing.T) {
	// Generate some test public keys
	pubKey1, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pubKey2, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pubKey3, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	pubKeys := []*secp256k1.PublicKey{pubKey1.PubKey(), pubKey2.PubKey(), pubKey3.PubKey()}

	// Create a script for 3-of-3 multisig using CHECKSIGADD
	scriptBuilder := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(pubKeys[0])).
		AddOp(txscript.OP_CHECKSIG).
		AddData(schnorr.SerializePubKey(pubKeys[1])).
		AddOp(txscript.OP_CHECKSIGADD).
		AddData(schnorr.SerializePubKey(pubKeys[2])).
		AddOp(txscript.OP_CHECKSIGADD).
		AddInt64(3).
		AddOp(txscript.OP_EQUAL)

	script, err := scriptBuilder.Script()
	require.NoError(t, err, "failed to build script")

	// Decode the script
	multisigClosure := &tree.MultisigClosure{}
	valid, err := multisigClosure.Decode(script)
	require.NoError(t, err, "failed to decode script")
	require.True(t, valid, "script should be valid")
	require.Equal(t, tree.MultisigTypeChecksigAdd, multisigClosure.Type, "expected MultisigTypeChecksigAdd")
	require.Equal(t, 3, len(multisigClosure.PubKeys), "expected 3 public keys")
}
