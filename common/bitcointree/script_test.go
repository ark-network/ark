package bitcointree_test

import (
	"testing"

	"github.com/ark-network/ark/common/bitcointree"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

func TestRoundTripCSV(t *testing.T) {
	seckey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	csvSig := &bitcointree.CSVSigClosure{
		Pubkey:  seckey.PubKey(),
		Seconds: 1024,
	}

	leaf, err := csvSig.Leaf()
	require.NoError(t, err)

	var cl bitcointree.CSVSigClosure

	valid, err := cl.Decode(leaf.Script)
	require.NoError(t, err)
	require.True(t, valid)

	require.Equal(t, csvSig.Seconds, cl.Seconds)
}
