package bitcointree

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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

type Musig2Nonce struct {
	PubNonce [66]byte
}

func (n *Musig2Nonce) Encode(w io.Writer) error {
	_, err := w.Write(n.PubNonce[:])
	return err
}

func (n *Musig2Nonce) Decode(r io.Reader) error {
	bytes := make([]byte, 66)
	bytesRead, err := io.ReadFull(r, bytes)
	if err != nil {
		return err
	}
	if bytesRead != 66 {
		return fmt.Errorf("expected to read 66 bytes, but read %d", bytesRead)
	}

	copy(n.PubNonce[:], bytes)
	return nil
}

type TreeNonces [][]*Musig2Nonce // public nonces
type TreePartialSigs [][]*musig2.PartialSignature

type SignerSession interface {
	GetNonces() (TreeNonces, error)       // generate tree nonces for this session
	SetKeys([]*btcec.PublicKey) error     // set the cosigner public keys for this session
	SetAggregatedNonces(TreeNonces) error // set the aggregated nonces
	Sign() (TreePartialSigs, error)       // sign the tree
}

type CoordinatorSession interface {
	AddNonce(*btcec.PublicKey, TreeNonces) error
	AggregateNonces() (TreeNonces, error)
	AddSig(*btcec.PublicKey, TreePartialSigs) error
	// SignTree combines the signatures and add them to the tree's psbts
	SignTree() (tree.CongestionTree, error)
}

func (n TreeNonces) Encode(w io.Writer) error {
	matrix, err := encodeMatrix(n)
	if err != nil {
		return err
	}

	_, err = w.Write(matrix)
	return err
}

func DecodeNonces(r io.Reader) (TreeNonces, error) {
	return decodeMatrix(func() *Musig2Nonce { return new(Musig2Nonce) }, r)
}

func (s TreePartialSigs) Encode(w io.Writer) error {
	matrix, err := encodeMatrix(s)
	if err != nil {
		return err
	}

	_, err = w.Write(matrix)
	return err
}

func DecodeSignatures(r io.Reader) (TreePartialSigs, error) {
	return decodeMatrix(func() *musig2.PartialSignature { return new(musig2.PartialSignature) }, r)
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
		levelNonces := make([]*Musig2Nonce, 0)
		for _, nonce := range level {
			levelNonces = append(levelNonces, &Musig2Nonce{nonce.PubNonce})
		}
		nonces = append(nonces, levelNonces)
	}

	return nonces, nil
}

func (t *treeSignerSession) SetKeys(keys []*btcec.PublicKey) error {
	if t.keys != nil {
		return errors.New("keys already set")
	}

	aggregateKey, err := AggregateKeys(keys, t.scriptRoot)
	if err != nil {
		return err
	}

	factory, err := prevOutFetcherFactory(aggregateKey.FinalKey, t.tree, t.roundSharedOutputAmount)
	if err != nil {
		return err
	}

	t.prevoutFetcherFactory = factory
	t.keys = keys

	return nil
}

func (t *treeSignerSession) SetAggregatedNonces(nonces TreeNonces) error {
	if t.aggregateNonces != nil {
		return errors.New("nonces already set")
	}

	t.aggregateNonces = nonces
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
		myNonce.SecNonce, seckey, aggregatedNonce.PubNonce, t.keys, [32]byte(message),
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
		levelNonces := make([]*Musig2Nonce, 0)
		for j := range level {
			nonces := make([][66]byte, 0)
			for _, n := range t.nonces {
				nonces = append(nonces, n[i][j].PubNonce)
			}

			aggregatedNonce, err := musig2.AggregateNonces(nonces)
			if err != nil {
				return nil, err
			}

			levelNonces = append(levelNonces, &Musig2Nonce{aggregatedNonce})
		}

		aggregatedNonces = append(aggregatedNonces, levelNonces)
	}

	return aggregatedNonces, nil
}

// SignTree implements CoordinatorSession.
func (t *treeCoordinatorSession) SignTree() (tree.CongestionTree, error) {
	var missingSigs int
	for _, sig := range t.sigs {
		if sig == nil {
			missingSigs++
		}
	}

	if missingSigs > 0 {
		return nil, fmt.Errorf("missing %d signature(s)", missingSigs)
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

			var combinedNonce *secp256k1.PublicKey
			sigs := make([]*musig2.PartialSignature, 0)
			for _, sig := range t.sigs {
				s := sig[i][j]
				if s.R != nil {
					combinedNonce = s.R
				}
				sigs = append(sigs, s)
			}

			if combinedNonce == nil {
				return nil, errors.New("missing combined nonce")
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
				combinedNonce, sigs,
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

type writable interface {
	Encode(w io.Writer) error
}

type readable interface {
	Decode(r io.Reader) error
}

// encodeMatrix encode a matrix of serializable objects into a byte stream
func encodeMatrix[T writable](matrix [][]T) ([]byte, error) {
	var buf bytes.Buffer

	// Write number of rows
	if err := binary.Write(&buf, binary.LittleEndian, uint32(len(matrix))); err != nil {
		return nil, err
	}

	// For each row, write its length and then its elements
	for _, row := range matrix {
		// Write row length
		if err := binary.Write(&buf, binary.LittleEndian, uint32(len(row))); err != nil {
			return nil, err
		}
		// Write row data
		for _, cell := range row {
			if err := cell.Encode(&buf); err != nil {
				return nil, err
			}
		}
	}

	return buf.Bytes(), nil
}

// decodeMatrix decode a byte stream into a matrix of serializable objects
func decodeMatrix[T readable](factory func() T, data io.Reader) ([][]T, error) {
	var rowCount uint32

	// Read number of rows
	if err := binary.Read(data, binary.LittleEndian, &rowCount); err != nil {
		return nil, err
	}

	// Initialize matrix
	matrix := make([][]T, rowCount)

	// For each row, read its length and then its elements
	for i := uint32(0); i < rowCount; i++ {
		var colCount uint32
		// Read row length
		if err := binary.Read(data, binary.LittleEndian, &colCount); err != nil {
			return nil, err
		}

		// Initialize row
		row := make([]T, colCount)

		// Read row data
		for j := uint32(0); j < colCount; j++ {
			cell := factory()
			if err := cell.Decode(data); err != nil {
				return nil, err
			}
			row[j] = cell
		}

		matrix[i] = row
	}

	return matrix, nil
}
