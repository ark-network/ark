package tree_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

func fmtCode(t int) string {
	return fmt.Sprintf("%x", t)
}

type ClosureTestRun struct {
	run           string
	script        string
	expectedError bool
}

const (
	exPubKey1               = "f8352deebdf5658d95875d89656112b1dd150f176c702eea4f91a91527e48e26"
	exPubKey2               = "fc68d5ea9279cc9d2c57e6885e21bbaee9c3aec85089f1d6c705c017d321ea84"
	exHash                  = "628850CB844FE63C308C62AFC8BC5351F1952A7F"
	sequenceExample         = "03070040"
	disabledSequenceExample = "ffffffff"
	exampleLocktime         = "049a696167"
)

func TestDecodeClosure(t *testing.T) {
	var multisigClosureCases = []ClosureTestRun{
		{
			run: "multisig closure 1 key",
			script: fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: false,
		},
		{
			run: "multisig closure 2 public keys",
			script: fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: false,
		},
		{
			run: "multisig closure missing OP_CHECKSIG",
			script: fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2,
			expectedError: true,
		},
		{
			run: "multisig closure missing OP_DATA_32 for first pubkey",
			script: exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: true,
		},
		{
			run: "multisig closure OP_DATA_32 for second pubkey",
			script: fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: true,
		},
	}

	var csvMultisigClosureCases = []ClosureTestRun{
		{
			run: "csv multisig closure 1 key",
			script: sequenceExample +
				fmtCode(txscript.OP_CHECKSEQUENCEVERIFY) +
				fmtCode(txscript.OP_DROP) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: false,
		},
		{
			run: "csv multisig closure 2 pub keys",
			script: sequenceExample +
				fmtCode(txscript.OP_CHECKSEQUENCEVERIFY) +
				fmtCode(txscript.OP_DROP) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: false,
		},
		{
			run: "csv multisig closure missing sequence",
			script: fmtCode(txscript.OP_CHECKSEQUENCEVERIFY) +
				fmtCode(txscript.OP_DROP) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: true,
		},
		{
			run: "csv multisig closure missing OP_CHECKSEQUENCEVERIFY",
			script: sequenceExample +
				fmtCode(txscript.OP_DROP) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: true,
		},
		{
			run: "csv multisig closure disabled timelock sequence",
			script: disabledSequenceExample +
				fmtCode(txscript.OP_CHECKSEQUENCEVERIFY) +
				fmtCode(txscript.OP_DROP) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: true,
		},
	}

	var cltvMultisigClosureCases = []ClosureTestRun{
		{
			run: "cltv multisig closure 1 pub key",
			script: exampleLocktime +
				fmtCode(txscript.OP_CHECKLOCKTIMEVERIFY) +
				fmtCode(txscript.OP_DROP) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: false,
		},
		{
			run: "cltv multisig closure 2 pub keys",
			script: exampleLocktime +
				fmtCode(txscript.OP_CHECKLOCKTIMEVERIFY) +
				fmtCode(txscript.OP_DROP) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: false,
		},
		{
			run: "cltv multisig closure missing locktime",
			script: fmtCode(txscript.OP_CHECKLOCKTIMEVERIFY) +
				fmtCode(txscript.OP_DROP) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: true,
		},
		{
			run: "cltv multisig closure missing OP_CHECKLOCKTIMEVERIFY",
			script: exampleLocktime +
				fmtCode(txscript.OP_DROP) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: true,
		},
	}

	var conditionMultisigClosureCases = []ClosureTestRun{
		{
			run: "multisig closure with condition 2 nums that add up to 8",
			script: fmtCode(txscript.OP_5) +
				fmtCode(txscript.OP_3) +
				fmtCode(txscript.OP_2DUP) +
				fmtCode(txscript.OP_ADD) +
				fmtCode(txscript.OP_8) +
				fmtCode(txscript.OP_EQUALVERIFY) +
				fmtCode(txscript.OP_SUB) +
				fmtCode(txscript.OP_2) +
				fmtCode(txscript.OP_EQUAL) +
				fmtCode(txscript.OP_VERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: false,
		},
		{
			run: "multisig closure with condition verify secret against hash",
			script: fmtCode(txscript.OP_1) +
				fmtCode(txscript.OP_HASH160) +
				fmtCode(txscript.OP_DATA_20) +
				exHash +
				fmtCode(txscript.OP_EQUAL) +
				fmtCode(txscript.OP_VERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: false,
		},
		{
			run: "multisig closure with condition missing OP_VERIFY",
			script: fmtCode(txscript.OP_1) +
				fmtCode(txscript.OP_HASH160) +
				fmtCode(txscript.OP_DATA_20) +
				exHash +
				fmtCode(txscript.OP_EQUAL) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: true,
		},
	}

	var conditionCSVMultisigClosureCases = []ClosureTestRun{
		{
			run: "csv multisig closure with condition verify secret against hash",
			script: fmtCode(txscript.OP_1) +
				fmtCode(txscript.OP_HASH160) +
				fmtCode(txscript.OP_DATA_20) +
				exHash +
				fmtCode(txscript.OP_EQUAL) +
				fmtCode(txscript.OP_VERIFY) +
				sequenceExample +
				fmtCode(txscript.OP_CHECKSEQUENCEVERIFY) +
				fmtCode(txscript.OP_DROP) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: false,
		},
		{
			run: "csv multisig closure with condition missing OP_VERIFY",
			script: fmtCode(txscript.OP_1) +
				fmtCode(txscript.OP_HASH160) +
				fmtCode(txscript.OP_DATA_20) +
				exHash +
				fmtCode(txscript.OP_EQUAL) +
				sequenceExample +
				fmtCode(txscript.OP_CHECKSEQUENCEVERIFY) +
				fmtCode(txscript.OP_DROP) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: true,
		},
		{
			run: "csv multisig with condition missing sequence",
			script: fmtCode(txscript.OP_1) +
				fmtCode(txscript.OP_HASH160) +
				fmtCode(txscript.OP_DATA_20) +
				exHash +
				fmtCode(txscript.OP_EQUAL) +
				fmtCode(txscript.OP_VERIFY) +
				fmtCode(txscript.OP_CHECKSEQUENCEVERIFY) +
				fmtCode(txscript.OP_DROP) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: true,
		},
		{
			run: "csv multisig with condition missing OP_CHECKSEQUENCEVERIFY",
			script: fmtCode(txscript.OP_1) +
				fmtCode(txscript.OP_HASH160) +
				fmtCode(txscript.OP_DATA_20) +
				exHash +
				fmtCode(txscript.OP_EQUAL) +
				fmtCode(txscript.OP_VERIFY) +
				sequenceExample +
				fmtCode(txscript.OP_DROP) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: true,
		},
		{
			run: "csv multisig with condition disabled timelock sequence",
			script: fmtCode(txscript.OP_1) +
				fmtCode(txscript.OP_HASH160) +
				fmtCode(txscript.OP_DATA_20) +
				exHash +
				fmtCode(txscript.OP_EQUAL) +
				fmtCode(txscript.OP_VERIFY) +
				disabledSequenceExample +
				fmtCode(txscript.OP_CHECKSEQUENCEVERIFY) +
				fmtCode(txscript.OP_DROP) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey1 +
				fmtCode(txscript.OP_CHECKSIGVERIFY) +
				fmtCode(txscript.OP_DATA_32) +
				exPubKey2 +
				fmtCode(txscript.OP_CHECKSIG),
			expectedError: true,
		},
	}

	var cases = [][]ClosureTestRun{
		multisigClosureCases,
		csvMultisigClosureCases,
		cltvMultisigClosureCases,
		conditionMultisigClosureCases,
		conditionCSVMultisigClosureCases,
	}

	var mergedCases []ClosureTestRun
	for _, c := range cases {
		mergedCases = append(mergedCases, c...)
	}

	for _, testCase := range mergedCases {
		t.Run(testCase.run, func(t *testing.T) {
			scriptBytes, err := hex.DecodeString(testCase.script)
			require.NoError(t, err)
			closure, err := tree.DecodeClosure(scriptBytes)

			if testCase.expectedError {
				require.Nil(t, closure)
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, closure)
			}
		})
	}
}

func TestRoundTripCSV(t *testing.T) {
	seckey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	csvSig := &tree.CSVMultisigClosure{
		MultisigClosure: tree.MultisigClosure{
			PubKeys: []*secp256k1.PublicKey{seckey.PubKey()},
		},
		Locktime: common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 1024},
	}

	leaf, err := csvSig.Script()
	require.NoError(t, err)

	var cl tree.CSVMultisigClosure

	valid, err := cl.Decode(leaf)
	require.NoError(t, err)
	require.True(t, valid)

	require.Equal(t, csvSig.Locktime.Value, cl.Locktime.Value)
}

func TestMultisigClosure(t *testing.T) {
	// Generate some test keys
	prvkey1, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pubkey1 := prvkey1.PubKey()

	prvkey2, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pubkey2 := prvkey2.PubKey()

	t.Run("valid 2-of-2 multisig", func(t *testing.T) {
		closure := &tree.MultisigClosure{
			PubKeys: []*secp256k1.PublicKey{pubkey1, pubkey2},
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
			schnorr.SerializePubKey(pubkey1),
			schnorr.SerializePubKey(decodedClosure.PubKeys[0]),
		)
		require.Equal(t,
			schnorr.SerializePubKey(pubkey2),
			schnorr.SerializePubKey(decodedClosure.PubKeys[1]),
		)
	})

	t.Run("valid single key multisig", func(t *testing.T) {
		closure := &tree.MultisigClosure{
			PubKeys: []*secp256k1.PublicKey{pubkey1},
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
			schnorr.SerializePubKey(pubkey1),
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
		pubkeyBytes := schnorr.SerializePubKey(pubkey1)
		script := []byte{txscript.OP_DATA_32}
		script = append(script, pubkeyBytes...)
		// Missing OP_CHECKSIG

		closure := &tree.MultisigClosure{}
		valid, err := closure.Decode(script)
		require.NoError(t, err)
		require.False(t, valid)
	})

	t.Run("invalid script - extra data after checksig", func(t *testing.T) {
		pubkeyBytes := schnorr.SerializePubKey(pubkey1)
		script := []byte{txscript.OP_DATA_32}
		script = append(script, pubkeyBytes...)
		script = append(script, txscript.OP_CHECKSIG)
		script = append(script, 0x00) // Extra unwanted byte

		closure := &tree.MultisigClosure{}
		valid, err := closure.Decode(script)
		require.NoError(t, err)
		require.False(t, valid)
	})

	t.Run("witness size", func(t *testing.T) {
		closure := &tree.MultisigClosure{
			PubKeys: []*secp256k1.PublicKey{pubkey1, pubkey2},
		}

		require.Equal(t, 128, closure.WitnessSize()) // 64 * 2 bytes
	})

	t.Run("valid 12-of-12 multisig", func(t *testing.T) {
		// Generate 12 keys
		pubkeys := make([]*secp256k1.PublicKey, 12)
		for i := 0; i < 12; i++ {
			prvkey, err := secp256k1.GeneratePrivateKey()
			require.NoError(t, err)
			pubkeys[i] = prvkey.PubKey()
		}

		closure := &tree.MultisigClosure{
			PubKeys: pubkeys,
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
				schnorr.SerializePubKey(pubkeys[i]),
				schnorr.SerializePubKey(decodedClosure.PubKeys[i]),
			)
		}

		// Verify witness size is correct for 12 signatures
		require.Equal(t, 64*12, closure.WitnessSize())
	})
}

func TestCSVMultisigClosure(t *testing.T) {
	// Generate test keys
	prvkey1, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pubkey1 := prvkey1.PubKey()

	prvkey2, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pubkey2 := prvkey2.PubKey()

	t.Run("valid single key CSV", func(t *testing.T) {
		csvSig := &tree.CSVMultisigClosure{
			MultisigClosure: tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pubkey1},
			},
			Locktime: common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 1024},
		}

		script, err := csvSig.Script()
		require.NoError(t, err)

		decodedCSV := &tree.CSVMultisigClosure{}
		valid, err := decodedCSV.Decode(script)
		require.NoError(t, err)
		require.True(t, valid)
		require.Equal(t, uint32(1024), uint32(decodedCSV.Locktime.Value))
		require.Equal(t, 1, len(decodedCSV.PubKeys))
		require.Equal(t,
			schnorr.SerializePubKey(pubkey1),
			schnorr.SerializePubKey(decodedCSV.PubKeys[0]),
		)
	})

	t.Run("valid 2-of-2 CSV", func(t *testing.T) {
		csvSig := &tree.CSVMultisigClosure{
			MultisigClosure: tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pubkey1, pubkey2},
			},
			Locktime: common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 512 * 4}, // ~2 weeks
		}

		script, err := csvSig.Script()
		require.NoError(t, err)

		decodedCSV := &tree.CSVMultisigClosure{}
		valid, err := decodedCSV.Decode(script)
		require.NoError(t, err)
		require.True(t, valid)
		require.Equal(t, uint32(512*4), uint32(decodedCSV.Locktime.Value))
		require.Equal(t, 2, len(decodedCSV.PubKeys))
		require.Equal(t,
			schnorr.SerializePubKey(pubkey1),
			schnorr.SerializePubKey(decodedCSV.PubKeys[0]),
		)
		require.Equal(t,
			schnorr.SerializePubKey(pubkey2),
			schnorr.SerializePubKey(decodedCSV.PubKeys[1]),
		)
	})

	t.Run("invalid empty script", func(t *testing.T) {
		csvSig := &tree.CSVMultisigClosure{}
		valid, err := csvSig.Decode([]byte{})
		require.Error(t, err)
		require.False(t, valid)
	})

	t.Run("invalid CSV value", func(t *testing.T) {
		// Create a script with invalid CSV value
		pubkeyBytes := schnorr.SerializePubKey(pubkey1)
		script := []byte{txscript.OP_DATA_32}
		script = append(script, pubkeyBytes...)
		script = append(script, txscript.OP_CHECKSIG)
		script = append(script, 0xFF) // Invalid CSV value

		csvSig := &tree.CSVMultisigClosure{}
		valid, err := csvSig.Decode(script)
		require.NoError(t, err)
		require.False(t, valid)
	})

	t.Run("witness size", func(t *testing.T) {
		csvSig := &tree.CSVMultisigClosure{
			MultisigClosure: tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pubkey1, pubkey2},
			},
			Locktime: common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 1024},
		}
		// Should be same as multisig witness size (64 bytes per signature)
		require.Equal(t, 128, csvSig.WitnessSize())
	})

	t.Run("max timelock", func(t *testing.T) {
		csvSig := &tree.CSVMultisigClosure{
			MultisigClosure: tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pubkey1},
			},
			Locktime: common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: common.SECONDS_MAX}, // Maximum allowed value
		}

		script, err := csvSig.Script()
		require.NoError(t, err)

		decodedCSV := &tree.CSVMultisigClosure{}
		valid, err := decodedCSV.Decode(script)
		require.NoError(t, err)
		require.True(t, valid)
		require.Equal(t, uint32(common.SECONDS_MAX), decodedCSV.Locktime.Value)
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

func TestCSVMultisigClosureWitness(t *testing.T) {
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

	closure := &tree.CSVMultisigClosure{
		MultisigClosure: tree.MultisigClosure{
			PubKeys: []*secp256k1.PublicKey{pub1},
		},
		Locktime: common.RelativeLocktime{Type: common.LocktimeTypeBlock, Value: 144},
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
	pubkey1, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pubkey2, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pubkey3, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	pubkeys := []*secp256k1.PublicKey{pubkey1.PubKey(), pubkey2.PubKey(), pubkey3.PubKey()}

	// Create a script for 3-of-3 multisig using CHECKSIGADD
	scriptBuilder := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(pubkeys[0])).
		AddOp(txscript.OP_CHECKSIG).
		AddData(schnorr.SerializePubKey(pubkeys[1])).
		AddOp(txscript.OP_CHECKSIGADD).
		AddData(schnorr.SerializePubKey(pubkeys[2])).
		AddOp(txscript.OP_CHECKSIGADD).
		AddInt64(3).
		AddOp(txscript.OP_NUMEQUAL)

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

func TestCLTVMultisigClosure(t *testing.T) {
	// Generate test keys
	privkey1, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pubkey1 := privkey1.PubKey()

	privkey2, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pubkey2 := privkey2.PubKey()

	t.Run("valid single key with CLTV", func(t *testing.T) {
		closure := &tree.CLTVMultisigClosure{
			MultisigClosure: tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pubkey1},
				Type:    tree.MultisigTypeChecksig,
			},
			Locktime: common.AbsoluteLocktime(time.Now().Unix()),
		}

		script, err := closure.Script()
		require.NoError(t, err)

		decodedClosure := &tree.CLTVMultisigClosure{}
		valid, err := decodedClosure.Decode(script)
		require.NoError(t, err)
		require.True(t, valid)
		require.Equal(t, closure.Locktime, decodedClosure.Locktime)
		require.Equal(t, 1, len(decodedClosure.PubKeys))
		require.Equal(t, schnorr.SerializePubKey(pubkey1), schnorr.SerializePubKey(decodedClosure.PubKeys[0]))
	})

	t.Run("valid single key with CLTV height", func(t *testing.T) {
		closure := &tree.CLTVMultisigClosure{
			MultisigClosure: tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pubkey1},
				Type:    tree.MultisigTypeChecksig,
			},
			Locktime: common.AbsoluteLocktime(3000),
		}

		script, err := closure.Script()
		require.NoError(t, err)

		decodedClosure := &tree.CLTVMultisigClosure{}
		valid, err := decodedClosure.Decode(script)
		require.NoError(t, err)
		require.True(t, valid)
		require.Equal(t, closure.Locktime, decodedClosure.Locktime)
		require.Equal(t, 1, len(decodedClosure.PubKeys))
		require.Equal(t, schnorr.SerializePubKey(pubkey1), schnorr.SerializePubKey(decodedClosure.PubKeys[0]))
	})

	t.Run("valid two keys with CLTV", func(t *testing.T) {
		closure := &tree.CLTVMultisigClosure{
			MultisigClosure: tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pubkey1, pubkey2},
				Type:    tree.MultisigTypeChecksig,
			},
			Locktime: common.AbsoluteLocktime(time.Now().Unix()),
		}

		script, err := closure.Script()
		require.NoError(t, err)

		decodedClosure := &tree.CLTVMultisigClosure{}
		valid, err := decodedClosure.Decode(script)
		require.NoError(t, err)
		require.True(t, valid)
		require.Equal(t, closure.Locktime, decodedClosure.Locktime)
		require.Equal(t, 2, len(decodedClosure.PubKeys))
	})

	t.Run("valid two keys with CLTV using checksigadd", func(t *testing.T) {
		closure := &tree.CLTVMultisigClosure{
			MultisigClosure: tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pubkey1, pubkey2},
				Type:    tree.MultisigTypeChecksigAdd,
			},
			Locktime: common.AbsoluteLocktime(time.Now().Unix()),
		}

		script, err := closure.Script()
		require.NoError(t, err)

		decodedClosure := &tree.CLTVMultisigClosure{}
		valid, err := decodedClosure.Decode(script)
		require.NoError(t, err)
		require.True(t, valid)
		require.Equal(t, closure.Locktime, decodedClosure.Locktime)
		require.Equal(t, closure.Type, decodedClosure.Type)
		require.Equal(t, 2, len(decodedClosure.PubKeys))
	})

	t.Run("witness generation", func(t *testing.T) {
		closure := &tree.CLTVMultisigClosure{
			MultisigClosure: tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pubkey1, pubkey2},
				Type:    tree.MultisigTypeChecksig,
			},
			Locktime: common.AbsoluteLocktime(time.Now().Unix()),
		}

		controlBlock := bytes.Repeat([]byte{0x00}, 32)
		signatures := map[string][]byte{
			hex.EncodeToString(schnorr.SerializePubKey(pubkey1)): bytes.Repeat([]byte{0x01}, 64),
			hex.EncodeToString(schnorr.SerializePubKey(pubkey2)): bytes.Repeat([]byte{0x01}, 64),
		}

		witness, err := closure.Witness(controlBlock, signatures)
		require.NoError(t, err)
		require.Equal(t, 4, len(witness)) // 2 sigs + script + control block

		script, err := closure.Script()
		require.NoError(t, err)
		require.Equal(t, script, witness[2])
		require.Equal(t, controlBlock, witness[3])
	})

	t.Run("invalid cases", func(t *testing.T) {
		validClosure := &tree.CLTVMultisigClosure{
			MultisigClosure: tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pubkey1},
				Type:    tree.MultisigTypeChecksig,
			},
			Locktime: common.AbsoluteLocktime(time.Now().Unix()),
		}
		script, err := validClosure.Script()
		require.NoError(t, err)
		emptyScriptErr := "empty script"

		testCases := []struct {
			name   string
			script []byte
			err    *string
		}{
			{
				name:   "empty script",
				script: []byte{},
				err:    &emptyScriptErr,
			},
			{
				name:   "invalid CLTV index",
				script: append([]byte{txscript.OP_CHECKLOCKTIMEVERIFY, txscript.OP_DROP}, script...),
			},
			{
				name:   "missing CLTV",
				script: script[5:],
			},
			{
				name:   "invalid multisig after CLTV",
				script: append(script[:len(script)-1], txscript.OP_CHECKSIGVERIFY),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				closure := &tree.CLTVMultisigClosure{}
				valid, err := closure.Decode(tc.script)
				require.False(t, valid)
				if tc.err != nil {
					require.Contains(t, err.Error(), *tc.err)
				} else {
					require.NoError(t, err)
				}
			})
		}
	})
}

func TestExecuteBoolScript(t *testing.T) {
	// Generate two random byte slices for coinflip
	rand1 := make([]byte, 16)
	_, err := rand.Read(rand1)
	require.NoError(t, err)
	hash1 := sha256.Sum256(rand1)

	rand2 := make([]byte, 15)
	_, err = rand.Read(rand2)
	require.NoError(t, err)

	testCases := []struct {
		name        string
		script      []byte
		witness     wire.TxWitness
		returnValue bool
		expectErr   bool
	}{
		{
			name:        "True",
			script:      []byte{txscript.OP_TRUE},
			witness:     wire.TxWitness{},
			returnValue: true,
			expectErr:   false,
		},
		{
			name:        "False",
			script:      []byte{txscript.OP_FALSE},
			witness:     wire.TxWitness{},
			returnValue: false,
			expectErr:   false,
		},
		{
			name:        "invalid CHECKSIG",
			script:      []byte{txscript.OP_CHECKSIG},
			witness:     wire.TxWitness{},
			returnValue: false,
			expectErr:   true,
		},
		{
			name:        "invalid CHECKSIGADD",
			script:      []byte{txscript.OP_CHECKSIGADD},
			witness:     wire.TxWitness{},
			returnValue: false,
			expectErr:   true,
		},
		{
			name:        "invalid CHECKSIGVERIFY",
			script:      []byte{txscript.OP_CHECKSIGVERIFY},
			witness:     wire.TxWitness{},
			returnValue: false,
			expectErr:   true,
		},
		{
			name:        "invalid CLTV",
			script:      []byte{txscript.OP_CHECKLOCKTIMEVERIFY},
			witness:     wire.TxWitness{},
			returnValue: false,
			expectErr:   true,
		},
		{
			name:        "invalid CHECKSIGVERIFY",
			script:      []byte{txscript.OP_CHECKSIGVERIFY},
			witness:     wire.TxWitness{},
			returnValue: false,
			expectErr:   true,
		},
		{
			name:        "invalid zero elements on the stack",
			script:      []byte{txscript.OP_TRUE, txscript.OP_VERIFY},
			witness:     wire.TxWitness{},
			returnValue: false,
			expectErr:   true,
		},
		{
			name:        "invalid two elements on the stack",
			script:      []byte{txscript.OP_TRUE, txscript.OP_TRUE},
			witness:     wire.TxWitness{},
			returnValue: false,
			expectErr:   true,
		},
		{
			name:        "valid SHA256",
			script:      append(append([]byte{txscript.OP_SHA256, txscript.OP_DATA_32}, hash1[:]...), txscript.OP_EQUAL),
			witness:     wire.TxWitness{rand1},
			returnValue: true,
			expectErr:   false,
		},
		{
			name:        "invalid SHA256",
			script:      append(append([]byte{txscript.OP_SHA256, txscript.OP_DATA_32}, hash1[:]...), txscript.OP_EQUAL),
			witness:     wire.TxWitness{rand2},
			returnValue: false,
			expectErr:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := tree.ExecuteBoolScript(tc.script, tc.witness)

			if tc.expectErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.returnValue, valid)
		})
	}
}

func TestConditionMultisigClosure(t *testing.T) {
	// Generate test keys
	privkey1, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pubkey1 := privkey1.PubKey()

	privkey2, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pubkey2 := privkey2.PubKey()

	t.Run("valid condition with single key", func(t *testing.T) {
		// Create a simple condition script that just returns true
		conditionScript := []byte{txscript.OP_TRUE}

		closure := &tree.ConditionMultisigClosure{
			MultisigClosure: tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pubkey1},
				Type:    tree.MultisigTypeChecksig,
			},
			Condition: conditionScript,
		}

		script, err := closure.Script()
		require.NoError(t, err)

		decodedClosure := &tree.ConditionMultisigClosure{}
		valid, err := decodedClosure.Decode(script)
		require.NoError(t, err)
		require.True(t, valid)
		require.Equal(t, 1, len(decodedClosure.PubKeys))
		require.True(t, bytes.Equal(conditionScript, decodedClosure.Condition))
		require.True(t, bytes.Equal(schnorr.SerializePubKey(pubkey1), schnorr.SerializePubKey(decodedClosure.PubKeys[0])))
	})

	t.Run("valid condition with 2 of 2 multisig", func(t *testing.T) {
		randomBytes := make([]byte, 32)
		_, err := rand.Read(randomBytes)
		require.NoError(t, err)

		hash := sha256.Sum256(randomBytes)

		conditionScript := append([]byte{
			txscript.OP_SHA256,
			txscript.OP_DATA_32,
		}, hash[:]...)
		conditionScript = append(conditionScript, txscript.OP_EQUAL)

		closure := &tree.ConditionMultisigClosure{
			MultisigClosure: tree.MultisigClosure{
				PubKeys: []*secp256k1.PublicKey{pubkey1, pubkey2},
				Type:    tree.MultisigTypeChecksig,
			},
			Condition: conditionScript,
		}

		script, err := closure.Script()
		require.NoError(t, err)

		decodedClosure := &tree.ConditionMultisigClosure{}
		valid, err := decodedClosure.Decode(script)
		require.NoError(t, err)
		require.True(t, valid)
		require.Equal(t, 2, len(decodedClosure.PubKeys))
		require.True(t, bytes.Equal(conditionScript, decodedClosure.Condition))

		conditionWitness := [][]byte{randomBytes[:]}
		var conditionWitnessBytes bytes.Buffer
		require.NoError(t, psbt.WriteTxWitness(&conditionWitnessBytes, conditionWitness))

		signatures := map[string][]byte{
			hex.EncodeToString(schnorr.SerializePubKey(pubkey1)): bytes.Repeat([]byte{0x01}, 64),
			hex.EncodeToString(schnorr.SerializePubKey(pubkey2)): bytes.Repeat([]byte{0x02}, 64),
			tree.ConditionWitnessKey:                             conditionWitnessBytes.Bytes(),
		}

		controlBlock := bytes.Repeat([]byte{0x00}, 32)

		witness, err := closure.Witness(controlBlock, signatures)
		require.NoError(t, err)
		require.Equal(t, 5, len(witness)) // condition witness + 2 sigs + script + control block
		require.Equal(t, controlBlock, witness[len(witness)-1])
		require.Equal(t, conditionWitness[0], witness[2])
		require.Equal(t, script, witness[3])
		require.Equal(t, 64, len(witness[0]))
		require.Equal(t, 64, len(witness[1]))
	})
}
