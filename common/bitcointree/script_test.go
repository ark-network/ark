package bitcointree_test

import (
	"testing"

	"github.com/ark-network/ark/common/tree"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

func TestRoundTripCSV(t *testing.T) {
	seckey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	csvSig := &tree.CSVSigClosure{
		Pubkey:  seckey.PubKey(),
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
