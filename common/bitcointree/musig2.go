package bitcointree

import (
	"errors"
	"io"
	"strings"

	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	ErrCongestionTreeNotSet = errors.New("congestion tree not set")
	ErrAggregateKeyNotSet   = errors.New("aggregate key not set")
)

type TreeNonces [][][66]byte // public nonces
type TreePartialSigs [][]*musig2.PartialSignature

type SignerSession interface {
	GetNonces(*btcec.PublicKey) (TreeNonces, error)  // generate of return cached nonce for this session
	SetKeys([]*btcec.PublicKey, TreeNonces) error    // set the keys for this session (with the combined nonces)
	Sign(*btcec.PrivateKey) (TreePartialSigs, error) // sign the tree
}

type CoordinatorSession interface {
	AddNonce(*btcec.PublicKey, TreeNonces) error
	AggregateNonces() (TreeNonces, error)
	AddSig(*btcec.PublicKey, TreePartialSigs) error
	// SignTree combines the signatures and add them to the tree's psbts
	SignTree() (tree.CongestionTree, error)
}

func AggregateKeys(
	pubkeys []*btcec.PublicKey,
	scriptRoot []byte,
) (*musig2.AggregateKey, error) {
	key, _, _, err := musig2.AggregateKeys(pubkeys, true,
		musig2.WithTaprootKeyTweak(scriptRoot),
	)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func ValidateTreeSigs(
	minRelayFee int64,
	scriptRoot []byte,
	finalAggregatedKey *btcec.PublicKey,
	tree tree.CongestionTree,
) error {
	prevoutFetcher, err := prevOutFetcherFactory(minRelayFee, finalAggregatedKey)
	if err != nil {
		return err
	}

	for _, level := range tree {
		for _, node := range level {
			partialTx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
			if err != nil {
				return err
			}

			sig := partialTx.Inputs[0].TaprootKeySpendSig
			if len(sig) == 0 {
				return errors.New("unsigned tree input")
			}

			schnorrSig, err := schnorr.ParseSignature(sig)
			if err != nil {
				return err
			}

			inputFetcher := prevoutFetcher(partialTx)

			message, err := txscript.CalcTaprootSignatureHash(
				txscript.NewTxSigHashes(partialTx.UnsignedTx, inputFetcher),
				txscript.SigHashDefault,
				partialTx.UnsignedTx,
				0,
				inputFetcher,
			)
			if err != nil {
				return err
			}

			if !schnorrSig.Verify(message, finalAggregatedKey) {
				return errors.New("invalid signature")
			}
		}
	}

	return nil
}

func (n TreeNonces) Decode(r io.Reader, matrixFormat []int) error {
	for i := 0; i < len(matrixFormat); i++ {
		for j := 0; j < matrixFormat[i]; j++ {
			// read 66 bytes
			nonce := make([]byte, 66)
			_, err := r.Read(nonce)
			if err != nil {
				return err
			}

			n[i][j] = [66]byte(nonce)
		}
	}

	return nil
}

func (n TreeNonces) Encode(w io.Writer) error {
	for i := 0; i < len(n); i++ {
		for j := 0; j < len(n[i]); j++ {
			nonce := n[i][j][:]
			_, err := w.Write(nonce)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (n TreePartialSigs) Decode(r io.Reader, matrixFormat []int) error {
	for i := 0; i < len(matrixFormat); i++ {
		for j := 0; j < matrixFormat[i]; j++ {
			sig := &musig2.PartialSignature{}
			if err := sig.Decode(r); err != nil {
				return err
			}
		}
	}

	return nil
}

func (n TreePartialSigs) Encode(w io.Writer) error {
	for i := 0; i < len(n); i++ {
		for j := 0; j < len(n[i]); j++ {
			if err := n[i][j].Encode(w); err != nil {
				return err
			}
		}
	}

	return nil
}

func NewTreeSignerSession(
	congestionTree tree.CongestionTree,
	minRelayFee int64,
	scriptRoot []byte,
) SignerSession {
	return &treeSignerSession{
		tree:        congestionTree,
		minRelayFee: minRelayFee,
		scriptRoot:  scriptRoot,
	}
}

type treeSignerSession struct {
	tree            tree.CongestionTree
	myNonces        [][]*musig2.Nonces
	keys            []*btcec.PublicKey
	aggregateNonces TreeNonces
	minRelayFee     int64
	scriptRoot      []byte
	prevoutFetcher  func(*psbt.Packet) txscript.PrevOutputFetcher
}

func (t *treeSignerSession) generateNonces(key *btcec.PublicKey) error {
	if t.tree == nil {
		return ErrCongestionTreeNotSet
	}

	myNonces := make([][]*musig2.Nonces, 0)

	for _, level := range t.tree {
		levelNonces := make([]*musig2.Nonces, 0)
		for range level {
			nonce, err := musig2.GenNonces(
				musig2.WithPublicKey(key),
			)
			if err != nil {
				return err
			}

			levelNonces = append(levelNonces, nonce)
		}
		myNonces = append(myNonces, levelNonces)
	}

	t.myNonces = myNonces
	return nil
}

func (t *treeSignerSession) GetNonces(key *btcec.PublicKey) (TreeNonces, error) {
	if t.tree == nil {
		return nil, ErrCongestionTreeNotSet
	}

	if t.myNonces == nil {
		if err := t.generateNonces(key); err != nil {
			return nil, err
		}
	}

	nonces := make(TreeNonces, 0)

	for _, level := range t.myNonces {
		levelNonces := make([][66]byte, 0)
		for _, nonce := range level {
			levelNonces = append(levelNonces, nonce.PubNonce)
		}
		nonces = append(nonces, levelNonces)
	}

	return nonces, nil
}

func (t *treeSignerSession) SetKeys(keys []*btcec.PublicKey, nonces TreeNonces) error {
	if t.keys != nil {
		return errors.New("keys already set")
	}

	if t.aggregateNonces != nil {
		return errors.New("nonces already set")
	}

	aggregateKey, err := AggregateKeys(keys, t.scriptRoot)
	if err != nil {
		return err
	}

	prevoutFetcher, err := prevOutFetcherFactory(t.minRelayFee, aggregateKey.FinalKey)
	if err != nil {
		return err
	}

	t.prevoutFetcher = prevoutFetcher
	t.aggregateNonces = nonces
	t.keys = keys

	return nil
}

func (t *treeSignerSession) Sign(seckey *secp256k1.PrivateKey) (TreePartialSigs, error) {
	if t.tree == nil {
		return nil, ErrCongestionTreeNotSet
	}

	if t.keys == nil {
		return nil, ErrAggregateKeyNotSet
	}

	if t.aggregateNonces == nil {
		return nil, errors.New("nonces not set")
	}

	sigs := make(TreePartialSigs, 0)

	for i, level := range t.tree {
		levelSigs := make([]*musig2.PartialSignature, 0)

		for j, node := range level {
			partialTx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
			if err != nil {
				return nil, err
			}
			// sign the node
			sig, err := t.signPartial(partialTx, i, j, seckey)
			if err != nil {
				return nil, err
			}

			levelSigs = append(levelSigs, sig)
		}

		sigs = append(sigs, levelSigs)
	}

	return sigs, nil
}

func (t *treeSignerSession) signPartial(partialTx *psbt.Packet, posx int, posy int, seckey *btcec.PrivateKey) (*musig2.PartialSignature, error) {
	inputFetcher := t.prevoutFetcher(partialTx)

	myNonce := t.myNonces[posx][posy]
	aggregatedNonce := t.aggregateNonces[posx][posy]

	message, err := txscript.CalcTaprootSignatureHash(
		txscript.NewTxSigHashes(partialTx.UnsignedTx, inputFetcher),
		txscript.SigHashDefault,
		partialTx.UnsignedTx,
		0,
		inputFetcher,
	)
	if err != nil {
		return nil, err
	}

	return musig2.Sign(
		myNonce.SecNonce, seckey, aggregatedNonce, t.keys, [32]byte(message),
		musig2.WithSortedKeys(), musig2.WithTaprootSignTweak(t.scriptRoot),
	)
}

type treeCoordinatorSession struct {
	scriptRoot     []byte
	tree           tree.CongestionTree
	keys           []*btcec.PublicKey
	nonces         []TreeNonces
	sigs           []TreePartialSigs
	prevoutFetcher func(*psbt.Packet) txscript.PrevOutputFetcher
}

func NewTreeCoordinatorSession(congestionTree tree.CongestionTree, minRelayFee int64, scriptRoot []byte, keys []*btcec.PublicKey) (CoordinatorSession, error) {
	aggregateKey, err := AggregateKeys(keys, scriptRoot)
	if err != nil {
		return nil, err
	}

	prevoutFetcher, err := prevOutFetcherFactory(minRelayFee, aggregateKey.FinalKey)
	if err != nil {
		return nil, err
	}

	return &treeCoordinatorSession{
		scriptRoot:     scriptRoot,
		tree:           congestionTree,
		keys:           keys,
		nonces:         make([]TreeNonces, len(keys)),
		sigs:           make([]TreePartialSigs, len(keys)),
		prevoutFetcher: prevoutFetcher,
	}, nil
}

func (t *treeCoordinatorSession) getPubkeyIndex(pubkey *btcec.PublicKey) int {
	for i, key := range t.keys {
		if key.IsEqual(pubkey) {
			return i
		}
	}

	return -1
}

func (t *treeCoordinatorSession) AddNonce(pubkey *btcec.PublicKey, nonce TreeNonces) error {
	index := t.getPubkeyIndex(pubkey)
	if index == -1 {
		return errors.New("public key not found")
	}

	t.nonces[index] = nonce
	return nil
}

func (t *treeCoordinatorSession) AddSig(pubkey *btcec.PublicKey, sig TreePartialSigs) error {
	index := t.getPubkeyIndex(pubkey)
	if index == -1 {
		return errors.New("public key not found")
	}

	t.sigs[index] = sig
	return nil
}

func (t *treeCoordinatorSession) AggregateNonces() (TreeNonces, error) {
	for _, nonce := range t.nonces {
		if nonce == nil {
			return nil, errors.New("nonces not set")
		}
	}

	aggregatedNonces := make(TreeNonces, 0)

	for i, level := range t.tree {
		levelNonces := make([][66]byte, 0)
		for j := range level {

			nonces := make([][66]byte, 0)
			for _, n := range t.nonces {
				nonces = append(nonces, n[i][j])
			}

			aggregatedNonce, err := musig2.AggregateNonces(nonces)
			if err != nil {
				return nil, err
			}

			levelNonces = append(levelNonces, aggregatedNonce)
		}

		aggregatedNonces = append(aggregatedNonces, levelNonces)
	}

	return aggregatedNonces, nil
}

// SignTree implements CoordinatorSession.
func (t *treeCoordinatorSession) SignTree() (tree.CongestionTree, error) {
	for _, sig := range t.sigs {
		if sig == nil {
			return nil, errors.New("signatures not set")
		}
	}

	aggregatedKey, err := AggregateKeys(t.keys, t.scriptRoot)
	if err != nil {
		return nil, err
	}

	for i, level := range t.tree {
		for j, node := range level {
			partialTx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
			if err != nil {
				return nil, err
			}

			sigs := make([]*musig2.PartialSignature, 0)
			for _, sig := range t.sigs {
				sigs = append(sigs, sig[i][j])
			}

			inputFetcher := t.prevoutFetcher(partialTx)

			message, err := txscript.CalcTaprootSignatureHash(
				txscript.NewTxSigHashes(partialTx.UnsignedTx, inputFetcher),
				txscript.SigHashDefault,
				partialTx.UnsignedTx,
				0,
				inputFetcher,
			)

			combinedSig := musig2.CombineSigs(
				sigs[0].R, sigs,
				musig2.WithTaprootTweakedCombine([32]byte(message), t.keys, t.scriptRoot, true),
			)
			if err != nil {
				return nil, err
			}

			if !combinedSig.Verify(message, aggregatedKey.FinalKey) {
				return nil, errors.New("invalid signature")
			}

			partialTx.Inputs[0].TaprootKeySpendSig = combinedSig.Serialize()

			encodedSignedTx, err := partialTx.B64Encode()
			if err != nil {
				return nil, err
			}

			node.Tx = encodedSignedTx
			t.tree[i][j] = node
		}
	}

	return t.tree, nil
}

// given a final aggregated key and a min-relay-fee, returns the expected prevout
func prevOutFetcherFactory(
	feeAmount int64, finalAggregatedKey *btcec.PublicKey,
) (
	func(partial *psbt.Packet) txscript.PrevOutputFetcher, error,
) {
	pkscript, err := taprootOutputScript(finalAggregatedKey)
	if err != nil {
		return nil, err
	}

	return func(partial *psbt.Packet) txscript.PrevOutputFetcher {
		outputsAmount := int64(0)
		for _, output := range partial.UnsignedTx.TxOut {
			outputsAmount += output.Value
		}

		return &treePrevOutFetcher{
			prevout: &wire.TxOut{
				Value:    outputsAmount + feeAmount,
				PkScript: pkscript,
			},
		}
	}, nil
}

type treePrevOutFetcher struct {
	prevout *wire.TxOut
}

func (f *treePrevOutFetcher) FetchPrevOutput(wire.OutPoint) *wire.TxOut {
	return f.prevout
}
