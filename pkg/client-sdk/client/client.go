package client

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	GrpcClient = "grpc"
	RestClient = "rest"
)

var (
	ErrConnectionClosedByServer = fmt.Errorf("connection closed by server")
)

type RoundEvent interface {
	isRoundEvent()
}

type TransportClient interface {
	GetInfo(ctx context.Context) (*Info, error)
	RegisterInputsForNextRound(
		ctx context.Context, inputs []Input,
	) (string, error)
	RegisterIntent(
		ctx context.Context, signature, message string,
	) (string, error)
	DeleteIntent(ctx context.Context, requestID, signature, message string) error
	ConfirmRegistration(ctx context.Context, intentID string) error
	RegisterOutputsForNextRound(
		ctx context.Context, requestID string, outputs []Output, cosignersPublicKeys []string,
	) error
	SubmitTreeNonces(
		ctx context.Context, roundID, cosignerPubkey string, nonces tree.TreeNonces,
	) error
	SubmitTreeSignatures(
		ctx context.Context, roundID, cosignerPubkey string, signatures tree.TreePartialSigs,
	) error
	SubmitSignedForfeitTxs(
		ctx context.Context, signedForfeitTxs []string, signedRoundTx string,
	) error
	GetEventStream(ctx context.Context) (<-chan RoundEventChannel, func(), error)
	SubmitOffchainTx(
		ctx context.Context, virtualTx string, checkpointsTxs []string,
	) (signedCheckpointsTxs []string, signedVirtualTx, virtualTxid string, err error)
	FinalizeOffchainTx(
		ctx context.Context, virtualTxid string, checkpointsTxs []string,
	) error
	ListVtxos(ctx context.Context, addr string) ([]Vtxo, []Vtxo, error)
	GetRound(ctx context.Context, txID string) (*Round, error)
	GetRoundByID(ctx context.Context, roundID string) (*Round, error)
	Close()
	GetTransactionsStream(ctx context.Context) (<-chan TransactionEvent, func(), error)
	SubscribeForAddress(ctx context.Context, address string) (<-chan AddressEvent, func(), error)
}

type Info struct {
	Version                 string
	PubKey                  string
	VtxoTreeExpiry          int64
	UnilateralExitDelay     int64
	RoundInterval           int64
	Network                 string
	Dust                    uint64
	BoardingExitDelay       int64
	ForfeitAddress          string
	MarketHourStartTime     int64
	MarketHourEndTime       int64
	MarketHourPeriod        int64
	MarketHourRoundInterval int64
	UtxoMinAmount           int64
	UtxoMaxAmount           int64
	VtxoMinAmount           int64
	VtxoMaxAmount           int64
}

type RoundEventChannel struct {
	Event RoundEvent
	Err   error
}

type Outpoint struct {
	Txid string
	VOut uint32
}

func (o Outpoint) String() string {
	return fmt.Sprintf("%s:%d", o.Txid, o.VOut)
}

func (o Outpoint) Equals(other Outpoint) bool {
	return o.Txid == other.Txid && o.VOut == other.VOut
}

type Input struct {
	Outpoint
	Tapscripts []string
}

type Vtxo struct {
	Outpoint
	PubKey    string
	Amount    uint64
	RoundTxid string
	ExpiresAt time.Time
	CreatedAt time.Time
	RedeemTx  string
	IsPending bool
	SpentBy   string
	Swept     bool
	Spent     bool
}

func (v Vtxo) IsRecoverable() bool {
	return v.Swept && !v.Spent
}

func (v Vtxo) Address(server *secp256k1.PublicKey, net common.Network) (string, error) {
	pubkeyBytes, err := hex.DecodeString(v.PubKey)
	if err != nil {
		return "", err
	}

	pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
	if err != nil {
		return "", err
	}

	a := &common.Address{
		HRP:        net.Addr,
		Server:     server,
		VtxoTapKey: pubkey,
	}

	return a.Encode()
}

type TapscriptsVtxo struct {
	Vtxo
	Tapscripts []string
}

type Output struct {
	Address string // onchain or offchain address
	Amount  uint64
}

func (o Output) ToTxOut() (*wire.TxOut, bool, error) {
	var pkScript []byte
	isOnchain := false

	arkAddress, err := common.DecodeAddress(o.Address)
	if err != nil {
		// decode onchain address
		btcAddress, err := btcutil.DecodeAddress(o.Address, nil)
		if err != nil {
			return nil, false, err
		}

		pkScript, err = txscript.PayToAddrScript(btcAddress)
		if err != nil {
			return nil, false, err
		}

		isOnchain = true
	} else {
		pkScript, err = common.P2TRScript(arkAddress.VtxoTapKey)
		if err != nil {
			return nil, false, err
		}
	}

	if len(pkScript) == 0 {
		return nil, false, fmt.Errorf("invalid address")
	}

	return &wire.TxOut{
		Value:    int64(o.Amount),
		PkScript: pkScript,
	}, isOnchain, nil
}

type RoundStage int

func (s RoundStage) String() string {
	switch s {
	case RoundStageRegistration:
		return "ROUND_STAGE_REGISTRATION"
	case RoundStageFinalization:
		return "ROUND_STAGE_FINALIZATION"
	case RoundStageFinalized:
		return "ROUND_STAGE_FINALIZED"
	case RoundStageFailed:
		return "ROUND_STAGE_FAILED"
	default:
		return "ROUND_STAGE_UNDEFINED"
	}
}

const (
	RoundStageUndefined RoundStage = iota
	RoundStageRegistration
	RoundStageFinalization
	RoundStageFinalized
	RoundStageFailed
)

type Round struct {
	ID         string
	StartedAt  *time.Time
	EndedAt    *time.Time
	Tx         string
	Tree       tree.TxTree
	ForfeitTxs []string
	Connectors tree.TxTree
	Stage      RoundStage
}

type RoundFinalizationEvent struct {
	ID              string
	Tx              string
	ConnectorsIndex map[string]Outpoint // <txid:vout> -> outpoint
}

func (e RoundFinalizationEvent) isRoundEvent() {}

type RoundFinalizedEvent struct {
	ID   string
	Txid string
}

func (e RoundFinalizedEvent) isRoundEvent() {}

type RoundFailedEvent struct {
	ID     string
	Reason string
}

func (e RoundFailedEvent) isRoundEvent() {}

type RoundSigningStartedEvent struct {
	ID               string
	UnsignedRoundTx  string
	CosignersPubkeys []string
}

func (e RoundSigningStartedEvent) isRoundEvent() {}

type RoundSigningNoncesGeneratedEvent struct {
	ID     string
	Nonces tree.TreeNonces
}

func (e RoundSigningNoncesGeneratedEvent) isRoundEvent() {}

type BatchTreeEvent struct {
	ID         string
	Topic      []string
	BatchIndex int32
	Node       tree.Node
}

func (e BatchTreeEvent) isRoundEvent() {}

type BatchTreeSignatureEvent struct {
	ID         string
	Topic      []string
	BatchIndex int32
	Level      int32
	LevelIndex int32
	Signature  string
}

func (e BatchTreeSignatureEvent) isRoundEvent() {}

type BatchStartedEvent struct {
	ID             string
	IntentIdHashes []string
	BatchExpiry    int64
	ForfeitAddress string
}

func (e BatchStartedEvent) isRoundEvent() {}

type TransactionEvent struct {
	Round  *RoundTransaction
	Redeem *RedeemTransaction
	Err    error
}

type RoundTransaction struct {
	Txid                 string
	SpentVtxos           []Vtxo
	SpendableVtxos       []Vtxo
	ClaimedBoardingUtxos []Outpoint
	Hex                  string
}

type RedeemTransaction struct {
	Txid           string
	SpentVtxos     []Vtxo
	SpendableVtxos []Vtxo
	Hex            string
}

type AddressEvent struct {
	NewVtxos   []Vtxo
	SpentVtxos []Vtxo
	Err        error
}
