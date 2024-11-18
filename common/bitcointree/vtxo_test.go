package bitcointree_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/descriptor"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

func TestParseDescriptor(t *testing.T) {
	aspKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	aliceKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	aspPubKey := hex.EncodeToString(schnorr.SerializePubKey(aspKey.PubKey()))
	alicePubKey := hex.EncodeToString(schnorr.SerializePubKey(aliceKey.PubKey()))

	unspendableKey := hex.EncodeToString(bitcointree.UnspendableKey().SerializeCompressed())

	defaultScriptDescriptor := fmt.Sprintf(
		descriptor.DefaultVtxoDescriptorTemplate,
		unspendableKey,
		alicePubKey,
		aspPubKey,
		512,
		alicePubKey,
	)

	vtxo, err := bitcointree.ParseVtxoScript(defaultScriptDescriptor)
	require.NoError(t, err)

	require.IsType(t, &bitcointree.DefaultVtxoScript{}, vtxo)
	require.Equal(t, defaultScriptDescriptor, vtxo.ToDescriptor())
	require.Equal(t, alicePubKey, hex.EncodeToString(schnorr.SerializePubKey(vtxo.(*bitcointree.DefaultVtxoScript).Owner)))
	require.Equal(t, aspPubKey, hex.EncodeToString(schnorr.SerializePubKey(vtxo.(*bitcointree.DefaultVtxoScript).Asp)))
}
