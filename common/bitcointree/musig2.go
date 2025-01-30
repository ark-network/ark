package bitcointree

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"strings"
	"sync"

	"github.com/ark-network/ark/common"
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
	ErrMissingVtxoTree = errors.New("missing vtxo tree")
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

type TreeNonces [][]*Musig2Nonce // public nonces only
type TreePartialSigs [][]*musig2.PartialSignature

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

type SignerSession interface {
	Init(scriptRoot []byte, rootSharedOutputAmount int64, vtxoTree tree.VtxoTree) error
	GetPublicKey() string
	GetNonces() (TreeNonces, error) // generate tree nonces for this session
	SetAggregatedNonces(TreeNonces) // set the aggregated nonces
	Sign() (TreePartialSigs, error) // sign the tree
}

type CoordinatorSession interface {
	AddNonce(*btcec.PublicKey, TreeNonces)
	AddSignatures(*btcec.PublicKey, TreePartialSigs)
	AggregateNonces() (TreeNonces, error)
	// SignTree combines the signatures and add them to the tree's psbts
	SignTree() (tree.VtxoTree, error)
}

// AggregateKeys is a wrapper around musig2.AggregateKeys using the given scriptRoot as taproot tweak
func AggregateKeys(
	pubkeys []*btcec.PublicKey,
	scriptRoot []byte,
) (*musig2.AggregateKey, error) {
	if len(pubkeys) == 0 {
		return nil, errors.New("no pubkeys")
	}

	for _, pubkey := range pubkeys {
		if pubkey == nil {
			return nil, errors.New("nil pubkey")
		}
	}

	if scriptRoot == nil {
		return nil, errors.New("nil script root")
	}

	key, _, _, err := musig2.AggregateKeys(pubkeys, true,
		musig2.WithTaprootKeyTweak(scriptRoot),
	)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// ValidateTreeSigs iterates over the tree matrix and verify the TaprootKeySpendSig
// the public key is rebuilt from the keys set in the unknown field of the psbt
func ValidateTreeSigs(
	scriptRoot []byte,
	roundSharedOutputAmount int64,
	vtxoTree tree.VtxoTree,
) error {
	prevoutFetcherFactory, err := prevOutFetcherFactory(vtxoTree, roundSharedOutputAmount, scriptRoot)
	if err != nil {
		return err
	}

	return workPoolMatrix(vtxoTree, func(_, _ int, node tree.Node) error {
		partialTx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
		if err != nil {
			return fmt.Errorf("failed to parse tx: %w", err)
		}

		sig := partialTx.Inputs[0].TaprootKeySpendSig
		if len(sig) == 0 {
			return errors.New("unsigned tree input")
		}

		schnorrSig, err := schnorr.ParseSignature(sig)
		if err != nil {
			return fmt.Errorf("failed to parse signature: %w", err)
		}

		prevoutFetcher, err := prevoutFetcherFactory(partialTx)
		if err != nil {
			return fmt.Errorf("failed to get prevout fetcher: %w", err)
		}

		message, err := txscript.CalcTaprootSignatureHash(
			txscript.NewTxSigHashes(partialTx.UnsignedTx, prevoutFetcher),
			txscript.SigHashDefault,
			partialTx.UnsignedTx,
			0,
			prevoutFetcher,
		)
		if err != nil {
			return fmt.Errorf("failed to calculate sighash: %w", err)
		}

		keys, err := GetCosignerKeys(partialTx.Inputs[0])
		if err != nil {
			return fmt.Errorf("failed to get cosigner keys: %w", err)
		}

		if len(keys) == 0 {
			return fmt.Errorf("no keys for txid %s", partialTx.UnsignedTx.TxHash().String())
		}

		aggregateKey, err := AggregateKeys(keys, scriptRoot)
		if err != nil {
			return fmt.Errorf("failed to aggregate keys: %w", err)
		}

		if !schnorrSig.Verify(message, aggregateKey.FinalKey) {
			return fmt.Errorf("invalid signature for txid %s", partialTx.UnsignedTx.TxHash().String())
		}

		return nil
	})
}

func NewTreeSignerSession(signer *btcec.PrivateKey) SignerSession {
	return &treeSignerSession{secretKey: signer}
}

type treeSignerSession struct {
	secretKey             *btcec.PrivateKey
	txs                   [][]*psbt.Packet
	myNonces              [][]*musig2.Nonces
	aggregateNonces       TreeNonces
	scriptRoot            []byte
	prevoutFetcherFactory func(*psbt.Packet) (txscript.PrevOutputFetcher, error)
}

func (t *treeSignerSession) Init(scriptRoot []byte, rootSharedOutputAmount int64, vtxoTree tree.VtxoTree) error {
	prevOutFetcherFactory, err := prevOutFetcherFactory(vtxoTree, rootSharedOutputAmount, scriptRoot)
	if err != nil {
		return err
	}

	txs, err := vtxoTreeToTx(vtxoTree)
	if err != nil {
		return err
	}

	t.scriptRoot = scriptRoot
	t.txs = txs
	t.prevoutFetcherFactory = prevOutFetcherFactory
	return nil
}

func (t *treeSignerSession) GetPublicKey() string {
	return hex.EncodeToString(t.secretKey.PubKey().SerializeCompressed())
}

// GetNonces returns only the public musig2 nonces for each transaction
// where the signer's key is in the list of cosigners
func (t *treeSignerSession) GetNonces() (TreeNonces, error) {
	if len(t.txs) == 0 {
		return nil, ErrMissingVtxoTree
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
			if nonce == nil {
				levelNonces = append(levelNonces, nil)
				continue
			}

			levelNonces = append(levelNonces, &Musig2Nonce{nonce.PubNonce})
		}
		nonces = append(nonces, levelNonces)
	}

	return nonces, nil
}

func (t *treeSignerSession) SetAggregatedNonces(nonces TreeNonces) {
	t.aggregateNonces = nonces
}

// Sign generates the musig2 partial signatures for each transaction where the signer's key is in the list of keys
func (t *treeSignerSession) Sign() (TreePartialSigs, error) {
	if len(t.txs) == 0 {
		return nil, ErrMissingVtxoTree
	}

	if t.aggregateNonces == nil {
		return nil, errors.New("nonces not set")
	}

	sigs := make(TreePartialSigs, 0, len(t.txs))
	for i := range t.txs {
		sigs = append(sigs, make([]*musig2.PartialSignature, len(t.txs[i])))
	}

	signerPubKey := schnorr.SerializePubKey(t.secretKey.PubKey())

	if err := workPoolMatrix(t.txs, func(i, j int, partialTx *psbt.Packet) error {
		mustSign, keys, err := getCosignersPublicKeys(signerPubKey, partialTx)
		if err != nil {
			return err
		}

		// if the signer's key is not in the list of keys, skip signing
		if !mustSign {
			sigs[i][j] = nil
			return nil
		}

		// craft musig2 partial signature
		sig, err := t.signPartial(partialTx, i, j, keys)
		if err != nil {
			return fmt.Errorf("failed to sign partial tx: %w", err)
		}

		sigs[i][j] = sig
		return nil
	}); err != nil {
		return nil, err
	}

	return sigs, nil
}

// generateNonces iterates over the tree matrix and generates musig2 private and public nonces for each transaction
func (t *treeSignerSession) generateNonces() error {
	if len(t.txs) == 0 {
		return ErrMissingVtxoTree
	}

	signerPubKey := t.secretKey.PubKey()
	serializedSignerPubKey := schnorr.SerializePubKey(signerPubKey)

	myNonces := make([][]*musig2.Nonces, 0, len(t.txs))
	for i := range t.txs {
		myNonces = append(myNonces, make([]*musig2.Nonces, len(t.txs[i])))
	}

	err := workPoolMatrix(t.txs, func(i, j int, partialTx *psbt.Packet) error {
		mustGenerateNonce, _, err := getCosignersPublicKeys(serializedSignerPubKey, partialTx)
		if err != nil {
			return err
		}

		// if the signer's key is not in the list of keys, skip generating nonces
		if !mustGenerateNonce {
			myNonces[i][j] = nil
			return nil
		}

		// generate musig2 nonces
		nonce, err := musig2.GenNonces(
			musig2.WithPublicKey(signerPubKey),
		)
		if err != nil {
			return err
		}

		myNonces[i][j] = nonce
		return nil
	})

	if err != nil {
		return err
	}

	t.myNonces = myNonces
	return nil
}

// signPartial signs the given transaction at the position (posx, posy)
func (t *treeSignerSession) signPartial(
	partialTx *psbt.Packet,
	posx int, posy int,
	keys []*btcec.PublicKey,
) (*musig2.PartialSignature, error) {
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
		myNonce.SecNonce, t.secretKey, aggregatedNonce.PubNonce, keys, [32]byte(message),
		musig2.WithSortedKeys(), musig2.WithTaprootSignTweak(t.scriptRoot), musig2.WithFastSign(),
	)
}

type treeCoordinatorSession struct {
	scriptRoot            []byte
	nonces                map[string]TreeNonces      // xonly pubkey -> nonces
	sigs                  map[string]TreePartialSigs // xonly pubkey -> sigs
	prevoutFetcherFactory func(*psbt.Packet) (txscript.PrevOutputFetcher, error)
	txs                   [][]*psbt.Packet
	vtxoTree              tree.VtxoTree
}

func NewTreeCoordinatorSession(
	roundSharedOutputAmount int64,
	vtxoTree tree.VtxoTree,
	scriptRoot []byte,
) (CoordinatorSession, error) {
	prevoutFetcherFactory, err := prevOutFetcherFactory(vtxoTree, roundSharedOutputAmount, scriptRoot)
	if err != nil {
		return nil, err
	}

	txs, err := vtxoTreeToTx(vtxoTree)
	if err != nil {
		return nil, err
	}

	return &treeCoordinatorSession{
		scriptRoot:            scriptRoot,
		txs:                   txs,
		nonces:                make(map[string]TreeNonces),
		sigs:                  make(map[string]TreePartialSigs),
		prevoutFetcherFactory: prevoutFetcherFactory,
		vtxoTree:              vtxoTree,
	}, nil
}

func (t *treeCoordinatorSession) AddNonce(pubkey *btcec.PublicKey, nonce TreeNonces) {
	t.nonces[hex.EncodeToString(schnorr.SerializePubKey(pubkey))] = nonce
}

func (t *treeCoordinatorSession) AddSignatures(pubkey *btcec.PublicKey, sig TreePartialSigs) {
	t.sigs[hex.EncodeToString(schnorr.SerializePubKey(pubkey))] = sig
}

// AggregateNonces aggregates the musig2 nonces for each transaction in the tree
// it returns an error if any of the nonces are not set
func (t *treeCoordinatorSession) AggregateNonces() (TreeNonces, error) {
	for _, nonce := range t.nonces {
		if nonce == nil {
			return nil, errors.New("nonces not set")
		}
	}

	aggregatedNonces := make(TreeNonces, 0, len(t.txs))
	for i := range t.txs {
		aggregatedNonces = append(aggregatedNonces, make([]*Musig2Nonce, len(t.txs[i])))
	}

	err := workPoolMatrix(t.txs, func(i, j int, partialTx *psbt.Packet) error {
		keys, err := GetCosignerKeys(partialTx.Inputs[0])
		if err != nil {
			return fmt.Errorf("failed to get cosigner keys: %w", err)
		}

		if len(keys) == 0 {
			return fmt.Errorf("no keys for txid %s", partialTx.UnsignedTx.TxHash().String())
		}

		nonces := make([][66]byte, 0, len(keys))

		for _, key := range keys {
			keyStr := hex.EncodeToString(schnorr.SerializePubKey(key))
			nonceMatrix, ok := t.nonces[keyStr]
			if !ok {
				return fmt.Errorf("nonces not set for cosigner key %x", key.SerializeCompressed())
			}

			nonce := nonceMatrix[i][j]
			if nonce == nil {
				return fmt.Errorf("missing nonce for cosigner key %x", key.SerializeCompressed())
			}

			nonces = append(nonces, nonce.PubNonce)
		}

		if len(nonces) == 0 {
			return fmt.Errorf("missing nonces for txid %s", partialTx.UnsignedTx.TxHash().String())
		}

		if len(nonces) != len(keys) {
			return fmt.Errorf("wrong number of nonces for txid %s, expected %d got %d", partialTx.UnsignedTx.TxHash().String(), len(keys), len(nonces))
		}

		aggregatedNonce, err := musig2.AggregateNonces(nonces)
		if err != nil {
			return fmt.Errorf("failed to aggregate nonces: %w", err)
		}

		aggregatedNonces[i][j] = &Musig2Nonce{aggregatedNonce}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return aggregatedNonces, nil
}

// SignTree combines the signatures and add them to the tree's psbts
// it returns the vtxo tree with the signed transactions set as TaprootKeySpendSig
func (t *treeCoordinatorSession) SignTree() (tree.VtxoTree, error) {
	signedTree := make(tree.VtxoTree, 0, len(t.txs))
	for i := range t.txs {
		signedTree = append(signedTree, make([]tree.Node, len(t.txs[i])))
	}

	if err := workPoolMatrix(t.txs, func(i, j int, partialTx *psbt.Packet) error {
		keys, err := GetCosignerKeys(partialTx.Inputs[0])
		if err != nil {
			return err
		}

		if len(keys) == 0 {
			return fmt.Errorf("no keys for txid %s", partialTx.UnsignedTx.TxHash().String())
		}

		var combinedNonce *secp256k1.PublicKey
		sigs := make([]*musig2.PartialSignature, 0, len(keys))

		for _, key := range keys {
			sigMatrix, ok := t.sigs[hex.EncodeToString(schnorr.SerializePubKey(key))]
			if !ok {
				return fmt.Errorf("sigs not set for cosigner key %x", key.SerializeCompressed())
			}

			s := sigMatrix[i][j]
			if s == nil {
				return fmt.Errorf("missing signature for cosigner key %x", key.SerializeCompressed())
			}

			if s.R != nil {
				combinedNonce = s.R
			}
			sigs = append(sigs, s)
		}

		if combinedNonce == nil {
			return fmt.Errorf("missing combined nonce for txid %s", partialTx.UnsignedTx.TxHash().String())
		}

		prevoutFetcher, err := t.prevoutFetcherFactory(partialTx)
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

		if len(sigs) == 0 {
			return fmt.Errorf("missing signatures for txid %s", partialTx.UnsignedTx.TxHash().String())
		}

		if len(sigs) != len(keys) {
			return fmt.Errorf("wrong number of signatures for txid %s, expected %d got %d", partialTx.UnsignedTx.TxHash().String(), len(keys), len(sigs))
		}

		combinedSig := musig2.CombineSigs(
			combinedNonce, sigs,
			musig2.WithTaprootTweakedCombine([32]byte(message), keys, t.scriptRoot, true),
		)

		aggregatedKey, err := AggregateKeys(keys, t.scriptRoot)
		if err != nil {
			return err
		}

		if !combinedSig.Verify(message, aggregatedKey.FinalKey) {
			return fmt.Errorf("invalid signature for cosigner key %x, txid %s", keys[0].SerializeCompressed(), partialTx.UnsignedTx.TxHash().String())
		}

		partialTx.Inputs[0].TaprootKeySpendSig = combinedSig.Serialize()

		encodedSignedTx, err := partialTx.B64Encode()
		if err != nil {
			return err
		}

		signedTree[i][j] = tree.Node{
			Txid:       t.vtxoTree[i][j].Txid,
			Tx:         encodedSignedTx,
			ParentTxid: t.vtxoTree[i][j].ParentTxid,
			Leaf:       t.vtxoTree[i][j].Leaf,
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return signedTree, nil
}

func prevOutFetcherFactory(
	vtxoTree tree.VtxoTree,
	roundSharedOutputAmount int64,
	scriptRoot []byte,
) (
	func(partial *psbt.Packet) (txscript.PrevOutputFetcher, error),
	error,
) {
	rootNode, err := vtxoTree.Root()
	if err != nil {
		return nil, err
	}

	return func(partial *psbt.Packet) (txscript.PrevOutputFetcher, error) {
		parentOutpoint := partial.UnsignedTx.TxIn[0].PreviousOutPoint
		parentTxID := parentOutpoint.Hash.String()
		if rootNode.ParentTxid == parentTxID {
			keys, err := GetCosignerKeys(partial.Inputs[0])
			if err != nil {
				return nil, err
			}

			if len(keys) == 0 {
				return nil, fmt.Errorf("no keys for txid %s", partial.UnsignedTx.TxHash().String())
			}

			aggregateKey, err := AggregateKeys(keys, scriptRoot)
			if err != nil {
				return nil, err
			}

			pkscript, err := common.P2TRScript(aggregateKey.FinalKey)
			if err != nil {
				return nil, err
			}

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

		return &treePrevOutFetcher{
			prevout: parentTx.UnsignedTx.TxOut[parentOutpoint.Index],
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
		// for each row, write its length
		if err := binary.Write(&buf, binary.LittleEndian, uint32(len(row))); err != nil {
			return nil, err
		}
		// for each cell, write <isNil> | <cell> bytes
		for _, cell := range row {
			notNil := true
			if reflect.ValueOf(cell).IsNil() {
				notNil = false
			}
			if err := binary.Write(&buf, binary.LittleEndian, notNil); err != nil {
				return nil, err
			}

			if notNil {
				if err := cell.Encode(&buf); err != nil {
					return nil, err
				}
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
	matrix := make([][]T, 0, rowCount)
	// For each row, read its length and then its elements
	for i := uint32(0); i < rowCount; i++ {
		var colCount uint32
		// Read row length
		if err := binary.Read(data, binary.LittleEndian, &colCount); err != nil {
			return nil, err
		}
		// Initialize row
		row := make([]T, 0, colCount)
		// Read row data
		for j := uint32(0); j < colCount; j++ {
			// check if the cell is nil
			var notNil bool
			if err := binary.Read(data, binary.LittleEndian, &notNil); err != nil {
				return nil, err
			}
			if !notNil {
				row = append(row, *new(T)) // append a new nil cell
				continue
			}
			cell := factory()
			if err := cell.Decode(data); err != nil {
				return nil, err
			}
			row = append(row, cell)
		}
		matrix = append(matrix, row)
	}

	return matrix, nil
}

func vtxoTreeToTx(vtxoTree tree.VtxoTree) ([][]*psbt.Packet, error) {
	txs := make([][]*psbt.Packet, 0)

	for _, level := range vtxoTree {
		levelTxs := make([]*psbt.Packet, 0)
		for _, node := range level {
			ptx, err := psbt.NewFromRawBytes(strings.NewReader(node.Tx), true)
			if err != nil {
				return nil, err
			}

			levelTxs = append(levelTxs, ptx)
		}

		txs = append(txs, levelTxs)
	}

	return txs, nil
}

// workPool is a generic worker pool that processes items concurrently
func workPool[T any](items []T, workers int, processItem func(item T) error) error {
	errChan := make(chan error, 1)
	workChan := make(chan T)

	var wg sync.WaitGroup
	wg.Add(workers)

	// launch workers
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for item := range workChan {
				if err := processItem(item); err != nil {
					select {
					case errChan <- err:
					default:
					}
					return
				}
			}
		}()
	}

	// distribute tasks
	go func() {
		for _, item := range items {
			select {
			case err := <-errChan:
				close(workChan)
				errChan <- err
				return
			default:
				workChan <- item
			}
		}
		close(workChan)
	}()

	// wait for all workers to finish
	wg.Wait()

	select {
	case err := <-errChan:
		return err
	default:
		return nil
	}
}

// workPoolMatrix is a specialized version of workPool for processing 2D matrices
func workPoolMatrix[T any](matrix [][]T, processItem func(i, j int, item T) error) error {
	type workItem struct {
		i, j int
		item T
	}

	// for each item in the matrix, create a work task
	items := make([]workItem, 0, len(matrix)*len(matrix[0]))
	for i, row := range matrix {
		for j, item := range row {
			items = append(items, workItem{i: i, j: j, item: item})
		}
	}

	return workPool(items, runtime.NumCPU(), func(item workItem) error {
		return processItem(item.i, item.j, item.item)
	})
}

// getCosignersPublicKeys extract the set of cosigners public keys from the tx and check if the signer's key is in the set
func getCosignersPublicKeys(signerPubKey []byte, tx *psbt.Packet) (bool, []*secp256k1.PublicKey, error) {
	keys, err := GetCosignerKeys(tx.Inputs[0])
	if err != nil {
		return false, nil, err
	}

	for _, key := range keys {
		if bytes.Equal(schnorr.SerializePubKey(key), signerPubKey) {
			return true, keys, nil
		}
	}
	return false, nil, nil
}
