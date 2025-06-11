package grpcclient

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
)

// wrapper for GetEventStreamResponse and PingResponse
type eventResponse interface {
	GetBatchFailed() *arkv1.BatchFailed
	GetBatchStarted() *arkv1.BatchStartedEvent
	GetBatchFinalization() *arkv1.BatchFinalizationEvent
	GetBatchFinalized() *arkv1.BatchFinalizedEvent
	GetTreeSigningStarted() *arkv1.TreeSigningStartedEvent
	GetTreeNoncesAggregated() *arkv1.TreeNoncesAggregatedEvent
	GetTreeTx() *arkv1.TreeTxEvent
	GetTreeSignature() *arkv1.TreeSignatureEvent
}

type event struct {
	eventResponse
}

func (e event) toRoundEvent() (client.RoundEvent, error) {
	if ee := e.GetBatchFailed(); ee != nil {
		return client.RoundFailedEvent{
			ID:     ee.GetId(),
			Reason: ee.GetReason(),
		}, nil
	}

	if ee := e.GetBatchStarted(); ee != nil {
		return client.BatchStartedEvent{
			ID:             ee.GetId(),
			IntentIdHashes: ee.GetIntentIdHashes(),
			BatchExpiry:    ee.GetBatchExpiry(),
			ForfeitAddress: ee.GetForfeitAddress(),
		}, nil
	}

	if ee := e.GetBatchFinalization(); ee != nil {
		connectorsIndex := connectorsIndexFromProto{ee.GetConnectorsIndex()}.parse()

		return client.RoundFinalizationEvent{
			ID:              ee.GetId(),
			Tx:              ee.GetCommitmentTx(),
			ConnectorsIndex: connectorsIndex,
		}, nil
	}

	if ee := e.GetBatchFinalized(); ee != nil {
		return client.RoundFinalizedEvent{
			ID:   ee.GetId(),
			Txid: ee.GetCommitmentTxid(),
		}, nil
	}

	if ee := e.GetTreeSigningStarted(); ee != nil {
		return client.RoundSigningStartedEvent{
			ID:               ee.GetId(),
			UnsignedRoundTx:  ee.GetUnsignedCommitmentTx(),
			CosignersPubkeys: ee.GetCosignersPubkeys(),
		}, nil
	}

	if ee := e.GetTreeNoncesAggregated(); ee != nil {
		nonces, err := tree.DecodeNonces(hex.NewDecoder(strings.NewReader(ee.GetTreeNonces())))
		if err != nil {
			return nil, err
		}
		return client.RoundSigningNoncesGeneratedEvent{
			ID:     ee.GetId(),
			Nonces: nonces,
		}, nil
	}

	if ee := e.GetTreeTx(); ee != nil {
		treeTx := ee.GetTreeTx()

		return client.BatchTreeEvent{
			ID:         ee.GetId(),
			Topic:      ee.GetTopic(),
			BatchIndex: ee.GetBatchIndex(),
			Node: tree.Node{
				Txid:       treeTx.GetTxid(),
				Tx:         treeTx.GetTx(),
				ParentTxid: treeTx.GetParentTxid(),
				Level:      treeTx.GetLevel(),
				LevelIndex: treeTx.GetLevelIndex(),
				Leaf:       treeTx.GetLeaf(),
			},
		}, nil
	}

	if ee := e.GetTreeSignature(); ee != nil {
		return client.BatchTreeSignatureEvent{
			ID:         ee.GetId(),
			Topic:      ee.GetTopic(),
			BatchIndex: ee.GetBatchIndex(),
			Level:      ee.GetLevel(),
			LevelIndex: ee.GetLevelIndex(),
			Signature:  ee.GetSignature(),
		}, nil
	}

	return nil, fmt.Errorf("unknown event")
}

type vtxo struct {
	*arkv1.Vtxo
}

func (v vtxo) toVtxo() client.Vtxo {
	return client.Vtxo{
		Outpoint: client.Outpoint{
			Txid: v.GetOutpoint().GetTxid(),
			VOut: v.GetOutpoint().GetVout(),
		},
		Amount:    v.GetAmount(),
		RoundTxid: v.GetCommitmentTxid(),
		ExpiresAt: time.Unix(v.GetExpiresAt(), 0),
		IsPending: v.GetPreconfirmed(),
		SpentBy:   v.GetSpentBy(),
		PubKey:    v.GetPubkey(),
		CreatedAt: time.Unix(v.GetCreatedAt(), 0),
		Swept:     v.GetSwept(),
		Spent:     v.GetSpent(),
	}
}

type vtxos []*arkv1.Vtxo

func (v vtxos) toVtxos() []client.Vtxo {
	list := make([]client.Vtxo, 0, len(v))
	for _, vv := range v {
		list = append(list, vtxo{vv}.toVtxo())
	}
	return list
}

type connectorsIndexFromProto struct {
	connectorsIndex map[string]*arkv1.Outpoint
}

func (c connectorsIndexFromProto) parse() map[string]client.Outpoint {
	connectorsIndex := make(map[string]client.Outpoint)
	for vtxoOutpointStr, connectorOutpoint := range c.connectorsIndex {
		connectorsIndex[vtxoOutpointStr] = client.Outpoint{
			Txid: connectorOutpoint.Txid,
			VOut: uint32(connectorOutpoint.Vout),
		}
	}
	return connectorsIndex
}
