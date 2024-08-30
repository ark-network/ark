package bitcointree

import (
	"bytes"
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

	columnSeparator = byte('|')
	rowSeparator    = byte('/')
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
	_, err := r.Read(bytes)
	if err != nil {
		return err
	}

	n.PubNonce = [66]byte(bytes)
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

func NewTreeSignerSession(
	signer *btcec.PrivateKey,
	congestionTree tree.CongestionTree,
	minRelayFee int64,
	scriptRoot []byte,
) SignerSession {
	return &treeSignerSession{
		secretKey:   signer,
		tree:        congestionTree,
		minRelayFee: minRelayFee,
		scriptRoot:  scriptRoot,
	}
}

type treeSignerSession struct {
	secretKey       *btcec.PrivateKey
	tree            tree.CongestionTree
	myNonces        [][]*musig2.Nonces
	keys            []*btcec.PublicKey
	aggregateNonces TreeNonces
	minRelayFee     int64
	scriptRoot      []byte
	prevoutFetcher  func(*psbt.Packet) txscript.PrevOutputFetcher
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

	prevoutFetcher, err := prevOutFetcherFactory(t.minRelayFee, aggregateKey.FinalKey)
	if err != nil {
		return err
	}

	t.prevoutFetcher = prevoutFetcher
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
		myNonce.SecNonce, seckey, aggregatedNonce.PubNonce, t.keys, [32]byte(message),
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

	nbOfKeys := len(keys)

	return &treeCoordinatorSession{
		scriptRoot:     scriptRoot,
		tree:           congestionTree,
		keys:           keys,
		nonces:         make([]TreeNonces, nbOfKeys),
		sigs:           make([]TreePartialSigs, nbOfKeys),
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

			inputFetcher := t.prevoutFetcher(partialTx)

			message, err := txscript.CalcTaprootSignatureHash(
				txscript.NewTxSigHashes(partialTx.UnsignedTx, inputFetcher),
				txscript.SigHashDefault,
				partialTx.UnsignedTx,
				0,
				inputFetcher,
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

type writable interface {
	Encode(w io.Writer) error
}

type readable interface {
	Decode(r io.Reader) error
}

// encodeMatrix encode a matrix of serializable objects into a byte stream
func encodeMatrix[T writable](matrix [][]T) ([]byte, error) {
	var buf bytes.Buffer

	for _, row := range matrix {
		for _, cell := range row {
			if err := buf.WriteByte(columnSeparator); err != nil {
				return nil, err
			}

			if err := cell.Encode(&buf); err != nil {
				return nil, err
			}
		}

		if err := buf.WriteByte(rowSeparator); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// decodeMatrix decode a byte stream into a matrix of serializable objects
func decodeMatrix[T readable](factory func() T, data io.Reader) ([][]T, error) {
	matrix := make([][]T, 0)
	row := make([]T, 0)

	for {
		separator := make([]byte, 1)

		if _, err := data.Read(separator); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		b := separator[0]

		if b == rowSeparator {
			matrix = append(matrix, row)
			row = make([]T, 0)
			continue
		}

		cell := factory()

		if err := cell.Decode(data); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		row = append(row, cell)
	}

	return matrix, nil
}
