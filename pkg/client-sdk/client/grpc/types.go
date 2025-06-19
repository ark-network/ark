package grpcclient

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/types"
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

func (e event) toBatchEvent() (client.BatchEvent, error) {
	if ee := e.GetBatchFailed(); ee != nil {
		return client.BatchFailedEvent{
			Id:     ee.GetId(),
			Reason: ee.GetReason(),
		}, nil
	}

	if ee := e.GetBatchStarted(); ee != nil {
		return client.BatchStartedEvent{
			Id:              ee.GetId(),
			HashedIntentIds: ee.GetIntentIdHashes(),
			BatchExpiry:     ee.GetBatchExpiry(),
		}, nil
	}

	if ee := e.GetBatchFinalization(); ee != nil {
		connectorsIndex := connectorsIndexFromProto{ee.GetConnectorsIndex()}.parse()

		return client.BatchFinalizationEvent{
			Id:              ee.GetId(),
			Tx:              ee.GetCommitmentTx(),
			ConnectorsIndex: connectorsIndex,
		}, nil
	}

	if ee := e.GetBatchFinalized(); ee != nil {
		return client.BatchFinalizedEvent{
			Id:   ee.GetId(),
			Txid: ee.GetCommitmentTxid(),
		}, nil
	}

	if ee := e.GetTreeSigningStarted(); ee != nil {
		return client.TreeSigningStartedEvent{
			Id:                   ee.GetId(),
			UnsignedCommitmentTx: ee.GetUnsignedCommitmentTx(),
			CosignersPubkeys:     ee.GetCosignersPubkeys(),
		}, nil
	}

	if ee := e.GetTreeNoncesAggregated(); ee != nil {
		nonces, err := tree.DecodeNonces(hex.NewDecoder(strings.NewReader(ee.GetTreeNonces())))
		if err != nil {
			return nil, err
		}
		return client.TreeNoncesAggregatedEvent{
			Id:     ee.GetId(),
			Nonces: nonces,
		}, nil
	}

	if ee := e.GetTreeTx(); ee != nil {
		treeTx := ee.GetTreeTx()

		return client.TreeTxEvent{
			Id:         ee.GetId(),
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
		return client.TreeSignatureEvent{
			Id:         ee.GetId(),
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

func (v vtxo) toVtxo() types.Vtxo {
	return types.Vtxo{
		VtxoKey: types.VtxoKey{
			Txid: v.GetOutpoint().GetTxid(),
			VOut: v.GetOutpoint().GetVout(),
		},
		Script:         v.GetScript(),
		Amount:         v.GetAmount(),
		CommitmentTxid: v.GetCommitmentTxid(),
		CreatedAt:      time.Unix(v.GetCreatedAt(), 0),
		ExpiresAt:      time.Unix(v.GetExpiresAt(), 0),
		Preconfirmed:   v.GetPreconfirmed(),
		Swept:          v.GetSwept(),
		Redeemed:       v.GetRedeemed(),
		Spent:          v.GetSpent(),
		SpentBy:        v.GetSpentBy(),
	}
}

type vtxos []*arkv1.Vtxo

func (v vtxos) toVtxos() []types.Vtxo {
	list := make([]types.Vtxo, 0, len(v))
	for _, vv := range v {
		list = append(list, vtxo{vv}.toVtxo())
	}
	return list
}

type connectorsIndexFromProto struct {
	connectorsIndex map[string]*arkv1.Outpoint
}

func (c connectorsIndexFromProto) parse() map[string]types.VtxoKey {
	connectorsIndex := make(map[string]types.VtxoKey)
	for vtxoOutpointStr, connectorOutpoint := range c.connectorsIndex {
		connectorsIndex[vtxoOutpointStr] = types.VtxoKey{
			Txid: connectorOutpoint.GetTxid(),
			VOut: connectorOutpoint.GetVout(),
		}
	}
	return connectorsIndex
}
