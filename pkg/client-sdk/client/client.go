package client

import (
	"context"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	GrpcClient = "grpc"
	RestClient = "rest"
)

var (
	ErrConnectionClosedByServer = fmt.Errorf("connection closed by server")
)

type BatchEvent interface {
	isBatchEvent()
}

type TransportClient interface {
	GetInfo(ctx context.Context) (*Info, error)
	RegisterIntent(ctx context.Context, signature, message string) (string, error)
	DeleteIntent(ctx context.Context, signature, message string) error
	ConfirmRegistration(ctx context.Context, intentID string) error
	SubmitTreeNonces(ctx context.Context, batchId, cosignerPubkey string, nonces tree.TreeNonces) error
	SubmitTreeSignatures(ctx context.Context, batchId, cosignerPubkey string, signatures tree.TreePartialSigs) error
	SubmitSignedForfeitTxs(ctx context.Context, signedForfeitTxs []string, signedCommitmentTx string) error
	GetEventStream(ctx context.Context) (<-chan BatchEventChannel, func(), error)
	SubmitTx(ctx context.Context, signedArkTx string, checkpointTxs []string) (
		arkTxid, finalArkTx string, signedCheckpointTxs []string, err error,
	)
	FinalizeTx(ctx context.Context, arkTxid string, finalCheckpointTxs []string) error
	GetTransactionsStream(ctx context.Context) (<-chan TransactionEvent, func(), error)
	Close()
}

type Info struct {
	Version                 string
	PubKey                  string
	VtxoTreeExpiry          int64
	UnilateralExitDelay     int64
	BoardingExitDelay       int64
	RoundInterval           int64
	Network                 string
	Dust                    uint64
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

type BatchEventChannel struct {
	Event BatchEvent
	Err   error
}

type Input struct {
	types.VtxoKey
	Tapscripts []string
}

type TapscriptsVtxo struct {
	types.Vtxo
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

type BatchFinalizationEvent struct {
	Id              string
	Tx              string
	ConnectorsIndex map[string]types.VtxoKey // <txid:vout> -> outpoint
}

func (e BatchFinalizationEvent) isBatchEvent() {}

type BatchFinalizedEvent struct {
	Id   string
	Txid string
}

func (e BatchFinalizedEvent) isBatchEvent() {}

type BatchFailedEvent struct {
	Id     string
	Reason string
}

func (e BatchFailedEvent) isBatchEvent() {}

type TreeSigningStartedEvent struct {
	Id                   string
	UnsignedCommitmentTx string
	CosignersPubkeys     []string
}

func (e TreeSigningStartedEvent) isBatchEvent() {}

type TreeNoncesAggregatedEvent struct {
	Id     string
	Nonces tree.TreeNonces
}

func (e TreeNoncesAggregatedEvent) isBatchEvent() {}

type TreeTxEvent struct {
	Id         string
	Topic      []string
	BatchIndex int32
	Node       tree.Node
}

func (e TreeTxEvent) isBatchEvent() {}

type TreeSignatureEvent struct {
	Id         string
	Topic      []string
	BatchIndex int32
	Level      int32
	LevelIndex int32
	Signature  string
}

func (e TreeSignatureEvent) isBatchEvent() {}

type BatchStartedEvent struct {
	Id              string
	HashedIntentIds []string
	BatchExpiry     int64
}

func (e BatchStartedEvent) isBatchEvent() {}

type TransactionEvent struct {
	CommitmentTx *TxNotification
	ArkTx        *TxNotification
	Err          error
}

type TxNotification struct {
	Txid           string
	TxHex          string
	SpentVtxos     []types.Vtxo
	SpendableVtxos []types.Vtxo
}
