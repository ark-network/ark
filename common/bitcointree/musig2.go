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
)

var (
	ErrCongestionTreeNotSet = errors.New("congestion tree not set")
	ErrAggregateKeyNotSet   = errors.New("aggregate key not set")
)

type TreeNonces [][][66]byte // public nonces
type TreePartialSigs [][]*musig2.PartialSignature

type SignerSession interface {
	GetNonces() (TreeNonces, error)               // generate of return cached nonce for this session
	SetKeys([]*btcec.PublicKey, TreeNonces) error // set the keys for this session (with the combined nonces)
	Sign() (TreePartialSigs, error)               // sign the tree
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
	scriptRoot []byte,
	finalAggregatedKey *btcec.PublicKey,
	roundSharedOutputAmount int64,
	vtxoTree tree.CongestionTree,
) error {
	prevoutFetcherFactory, err := prevOutFetcherFactory(finalAggregatedKey, vtxoTree, roundSharedOutputAmount)
	if err != nil {
		return err
	}

	for _, level := range vtxoTree {
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

			prevoutFetcher, err := prevoutFetcherFactory(partialTx)
			if err != nil {
				return err
			}

			message, err := txscript.CalcTaprootSignatureHash(
				txscript.NewTxSigHashes(partialTx.UnsignedTx, prevoutFetcher),
				txscript.SigHashDefault,
				partialTx.UnsignedTx,
				0,
				prevoutFetcher,
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
	signer *btcec.PrivateKey,
	roundSharedOutputAmount int64,
	vtxoTree tree.CongestionTree,
	scriptRoot []byte,
) SignerSession {
	return &treeSignerSession{
		secretKey:               signer,
		tree:                    vtxoTree,
		scriptRoot:              scriptRoot,
		roundSharedOutputAmount: roundSharedOutputAmount,
	}
}

type treeSignerSession struct {
	secretKey               *btcec.PrivateKey
	tree                    tree.CongestionTree
	myNonces                [][]*musig2.Nonces
	keys                    []*btcec.PublicKey
	aggregateNonces         TreeNonces
	scriptRoot              []byte
	roundSharedOutputAmount int64
	prevoutFetcherFactory   func(*psbt.Packet) (txscript.PrevOutputFetcher, error)
}

func (t *treeSignerSession) generateNonces() error {
	if t.tree == nil {
		return ErrCongestionTreeNotSet
	}

	myNonces := make([][]*musig2.Nonces, 0)

	for _, level := range t.tree {
		levelNonces := make([]*musig2.Nonces, 0)
		for range level {
			nonce, err := musig2.GenNonces(
				musig2.WithPublicKey(t.secretKey.PubKey()),
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

func (t *treeSignerSession) GetNonces() (TreeNonces, error) {
	if t.tree == nil {
		return nil, ErrCongestionTreeNotSet
	}

	if t.myNonces == nil {
		if err := t.generateNonces(); err != nil {
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

	prevoutFetcher, err := prevOutFetcherFactory(aggregateKey.FinalKey, t.tree, t.roundSharedOutputAmount)
	if err != nil {
		return err
	}

	t.prevoutFetcherFactory = prevoutFetcher
	t.aggregateNonces = nonces
	t.keys = keys

	return nil
}

func (t *treeSignerSession) Sign() (TreePartialSigs, error) {
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
			sig, err := t.signPartial(partialTx, i, j, t.secretKey)
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
	prevoutFetcher, err := t.prevoutFetcherFactory(partialTx)
	if err != nil {
		return nil, err
	}

	myNonce := t.myNonces[posx][posy]
	aggregatedNonce := t.aggregateNonces[posx][posy]

	message, err := txscript.CalcTaprootSignatureHash(
		txscript.NewTxSigHashes(partialTx.UnsignedTx, prevoutFetcher),
		txscript.SigHashDefault,
		partialTx.UnsignedTx,
		0,
		prevoutFetcher,
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
	scriptRoot            []byte
	tree                  tree.CongestionTree
	keys                  []*btcec.PublicKey
	nonces                []TreeNonces
	sigs                  []TreePartialSigs
	prevoutFetcherFactory func(*psbt.Packet) (txscript.PrevOutputFetcher, error)
}

func NewTreeCoordinatorSession(
	roundSharedOutputAmount int64,
	vtxoTree tree.CongestionTree,
	scriptRoot []byte,
	keys []*btcec.PublicKey,
) (CoordinatorSession, error) {
	aggregateKey, err := AggregateKeys(keys, scriptRoot)
	if err != nil {
		return nil, err
	}

	prevoutFetcherFactory, err := prevOutFetcherFactory(aggregateKey.FinalKey, vtxoTree, roundSharedOutputAmount)
	if err != nil {
		return nil, err
	}

	nbOfKeys := len(keys)

	return &treeCoordinatorSession{
		scriptRoot:            scriptRoot,
		tree:                  vtxoTree,
		keys:                  keys,
		nonces:                make([]TreeNonces, nbOfKeys),
		sigs:                  make([]TreePartialSigs, nbOfKeys),
		prevoutFetcherFactory: prevoutFetcherFactory,
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

			prevoutFetcher, err := t.prevoutFetcherFactory(partialTx)
			if err != nil {
				return nil, err
			}

			message, err := txscript.CalcTaprootSignatureHash(
				txscript.NewTxSigHashes(partialTx.UnsignedTx, prevoutFetcher),
				txscript.SigHashDefault,
				partialTx.UnsignedTx,
				0,
				prevoutFetcher,
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

func prevOutFetcherFactory(
	finalAggregatedKey *btcec.PublicKey,
	vtxoTree tree.CongestionTree,
	roundSharedOutputAmount int64,
) (
	func(partial *psbt.Packet) (txscript.PrevOutputFetcher, error),
	error,
) {
	pkscript, err := taprootOutputScript(finalAggregatedKey)
	if err != nil {
		return nil, err
	}

	rootNode, err := vtxoTree.Root()
	if err != nil {
		return nil, err
	}

	return func(partial *psbt.Packet) (txscript.PrevOutputFetcher, error) {
		parentOutpoint := partial.UnsignedTx.TxIn[0].PreviousOutPoint
		parentTxID := parentOutpoint.Hash.String()
		if rootNode.ParentTxid == parentTxID {
			return &treePrevOutFetcher{
				prevout: &wire.TxOut{
					Value:    roundSharedOutputAmount,
					PkScript: pkscript,
				},
			}, nil
		}

		var parent tree.Node
		for _, level := range vtxoTree {
			for _, n := range level {
				if n.Txid == parentTxID {
					parent = n
					break
				}
			}
		}

		if parent.Txid == "" {
			return nil, errors.New("parent tx not found")
		}

		parentTx, err := psbt.NewFromRawBytes(strings.NewReader(parent.Tx), true)
		if err != nil {
			return nil, err
		}

		parentValue := parentTx.UnsignedTx.TxOut[parentOutpoint.Index].Value

		return &treePrevOutFetcher{
			prevout: &wire.TxOut{
				Value:    parentValue,
				PkScript: pkscript,
			},
		}, nil
	}, nil
}

type treePrevOutFetcher struct {
	prevout *wire.TxOut
}

func (f *treePrevOutFetcher) FetchPrevOutput(wire.OutPoint) *wire.TxOut {
	return f.prevout
}
