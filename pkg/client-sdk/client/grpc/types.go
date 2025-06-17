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

type out client.Output

func (o out) toProto() *arkv1.Output {
	return &arkv1.Output{
		Address: o.Address,
		Amount:  o.Amount,
	}
}

type outs []client.Output

func (o outs) toProto() []*arkv1.Output {
	list := make([]*arkv1.Output, 0, len(o))
	for _, oo := range o {
		list = append(list, out(oo).toProto())
	}
	return list
}

// wrapper for GetEventStreamResponse and PingResponse
type eventResponse interface {
	GetRoundFailed() *arkv1.RoundFailed
	GetBatchStarted() *arkv1.BatchStartedEvent
	GetRoundFinalization() *arkv1.RoundFinalizationEvent
	GetRoundFinalized() *arkv1.RoundFinalizedEvent
	GetRoundSigning() *arkv1.RoundSigningEvent
	GetRoundSigningNoncesGenerated() *arkv1.RoundSigningNoncesGeneratedEvent
	GetBatchTree() *arkv1.BatchTreeEvent
	GetBatchTreeSignature() *arkv1.BatchTreeSignatureEvent
}

type event struct {
	eventResponse
}

func (e event) toRoundEvent() (client.RoundEvent, error) {
	if ee := e.GetRoundFailed(); ee != nil {
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
		}, nil
	}

	if ee := e.GetRoundFinalization(); ee != nil {
		connectorsIndex := connectorsIndexFromProto{ee.GetConnectorsIndex()}.parse()

		return client.RoundFinalizationEvent{
			ID:              ee.GetId(),
			Tx:              ee.GetRoundTx(),
			ConnectorsIndex: connectorsIndex,
		}, nil
	}

	if ee := e.GetRoundFinalized(); ee != nil {
		return client.RoundFinalizedEvent{
			ID:   ee.GetId(),
			Txid: ee.GetRoundTxid(),
		}, nil
	}

	if ee := e.GetRoundSigning(); ee != nil {
		return client.RoundSigningStartedEvent{
			ID:               ee.GetId(),
			UnsignedRoundTx:  ee.GetUnsignedRoundTx(),
			CosignersPubkeys: ee.GetCosignersPubkeys(),
		}, nil
	}

	if ee := e.GetRoundSigningNoncesGenerated(); ee != nil {
		nonces, err := tree.DecodeNonces(hex.NewDecoder(strings.NewReader(ee.GetTreeNonces())))
		if err != nil {
			return nil, err
		}
		return client.RoundSigningNoncesGeneratedEvent{
			ID:     ee.GetId(),
			Nonces: nonces,
		}, nil
	}

	if ee := e.GetBatchTree(); ee != nil {
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

	if ee := e.GetBatchTreeSignature(); ee != nil {
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
		RoundTxid: v.GetRoundTxid(),
		ExpiresAt: time.Unix(v.GetExpireAt(), 0),
		IsPending: v.GetIsPending(),
		RedeemTx:  v.GetRedeemTx(),
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

func toProtoInput(i client.Input) *arkv1.Input {
	return &arkv1.Input{
		Outpoint: &arkv1.Outpoint{
			Txid: i.Txid,
			Vout: i.VOut,
		},
		TaprootTree: &arkv1.Tapscripts{
			Scripts: i.Tapscripts,
		},
	}
}

type ins []client.Input

func (i ins) toProto() []*arkv1.Input {
	list := make([]*arkv1.Input, 0, len(i))
	for _, ii := range i {
		list = append(list, toProtoInput(ii))
	}
	return list
}

type treeFromProto struct {
	*arkv1.Tree
}

func (t treeFromProto) parse() tree.TxTree {
	levels := make(tree.TxTree, 0, len(t.GetLevels()))

	for _, level := range t.GetLevels() {
		nodes := make([]tree.Node, 0, len(level.Nodes))

		for _, node := range level.Nodes {
			nodes = append(nodes, tree.Node{
				Txid:       node.GetTxid(),
				Tx:         node.GetTx(),
				ParentTxid: node.GetParentTxid(),
				Leaf:       node.GetLeaf(),
				Level:      node.GetLevel(),
				LevelIndex: node.GetLevelIndex(),
			})
		}

		levels = append(levels, nodes)
	}

	return levels
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
