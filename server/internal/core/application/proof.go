package application

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// OwnershipProof is a proof that the owner of a vtxo has the secret key able to sign the forfeit leaf.
type OwnershipProof struct {
	ControlBlock *txscript.ControlBlock
	Script       []byte
	Signature    *schnorr.Signature
}

func (p OwnershipProof) validate(vtxo domain.Vtxo) error {
	// verify revealed script and extract user public key
	pubkey, err := decodeForfeitClosure(p.Script)
	if err != nil {
		return err
	}

	// verify control block
	rootHash := p.ControlBlock.RootHash(p.Script)
	vtxoTapKey := txscript.ComputeTaprootOutputKey(bitcointree.UnspendableKey(), rootHash)

	if hex.EncodeToString(schnorr.SerializePubKey(vtxoTapKey)) != vtxo.Pubkey {
		return fmt.Errorf("invalid control block")
	}

	// verify signature
	txhash, err := chainhash.NewHashFromStr(vtxo.Txid)
	if err != nil {
		return err
	}

	voutBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(voutBytes, vtxo.VOut)

	outpointBytes := append(txhash[:], voutBytes...)
	sigMsg := sha256.Sum256(outpointBytes)

	if !p.Signature.Verify(sigMsg[:], pubkey) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

func decodeForfeitClosure(script []byte) (*secp256k1.PublicKey, error) {
	var covenantLessForfeitClosure bitcointree.MultisigClosure

	if valid, err := covenantLessForfeitClosure.Decode(script); err == nil && valid {
		return covenantLessForfeitClosure.Pubkey, nil
	}

	var covenantForfeitClosure tree.CSVSigClosure
	if valid, err := covenantForfeitClosure.Decode(script); err == nil && valid {
		return covenantForfeitClosure.Pubkey, nil
	}

	return nil, fmt.Errorf("invalid forfeit closure script")
}
