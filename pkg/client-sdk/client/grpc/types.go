package grpcclient

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
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
	GetRoundFinalization() *arkv1.RoundFinalizationEvent
	GetRoundFinalized() *arkv1.RoundFinalizedEvent
	GetRoundSigning() *arkv1.RoundSigningEvent
	GetRoundSigningNoncesGenerated() *arkv1.RoundSigningNoncesGeneratedEvent
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
	if ee := e.GetRoundFinalization(); ee != nil {
		tree := treeFromProto{ee.GetVtxoTree()}.parse()
		return client.RoundFinalizationEvent{
			ID:              ee.GetId(),
			Tx:              ee.GetRoundTx(),
			Tree:            tree,
			Connectors:      ee.GetConnectors(),
			MinRelayFeeRate: chainfee.SatPerKVByte(ee.MinRelayFeeRate),
		}, nil
	}

	if ee := e.GetRoundFinalized(); ee != nil {
		return client.RoundFinalizedEvent{
			ID:   ee.GetId(),
			Txid: ee.GetRoundTxid(),
		}, nil
	}

	if ee := e.GetRoundSigning(); ee != nil {
		pubkeys := make([]*secp256k1.PublicKey, 0, len(ee.GetCosignersPubkeys()))
		for _, pubkey := range ee.GetCosignersPubkeys() {
			p, err := hex.DecodeString(pubkey)
			if err != nil {
				return nil, err
			}
			pk, err := secp256k1.ParsePubKey(p)
			if err != nil {
				return nil, err
			}
			pubkeys = append(pubkeys, pk)
		}

		return client.RoundSigningStartedEvent{
			ID:                  ee.GetId(),
			UnsignedTree:        treeFromProto{ee.GetUnsignedVtxoTree()}.parse(),
			CosignersPublicKeys: pubkeys,
			UnsignedRoundTx:     ee.GetUnsignedRoundTx(),
		}, nil
	}

	if ee := e.GetRoundSigningNoncesGenerated(); ee != nil {
		nonces, err := bitcointree.DecodeNonces(hex.NewDecoder(strings.NewReader(ee.GetTreeNonces())))
		if err != nil {
			return nil, err
		}
		return client.RoundSigningNoncesGeneratedEvent{
			ID:     ee.GetId(),
			Nonces: nonces,
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
		IsOOR:     v.GetIsOor(),
		RedeemTx:  v.GetRedeemTx(),
		SpentBy:   v.GetSpentBy(),
		Pubkey:    v.GetPubkey(),
		CreatedAt: time.Unix(v.GetCreatedAt(), 0),
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
		Descriptor_: i.Descriptor,
	}
}

func toAsyncProtoInput(i client.AsyncPaymentInput) *arkv1.AsyncPaymentInput {
	return &arkv1.AsyncPaymentInput{
		Input:           toProtoInput(i.Input),
		ForfeitLeafHash: i.ForfeitLeafHash.String(),
	}
}

type asyncIns []client.AsyncPaymentInput

func (i asyncIns) toProto() []*arkv1.AsyncPaymentInput {
	list := make([]*arkv1.AsyncPaymentInput, 0, len(i))
	for _, ii := range i {
		list = append(list, toAsyncProtoInput(ii))
	}
	return list
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

func (t treeFromProto) parse() tree.CongestionTree {
	levels := make(tree.CongestionTree, 0, len(t.GetLevels()))

	for _, level := range t.GetLevels() {
		nodes := make([]tree.Node, 0, len(level.Nodes))

		for _, node := range level.Nodes {
			nodes = append(nodes, tree.Node{
				Txid:       node.Txid,
				Tx:         node.Tx,
				ParentTxid: node.ParentTxid,
			})
		}

		levels = append(levels, nodes)
	}

	for j, treeLvl := range levels {
		for i, node := range treeLvl {
			if len(levels.Children(node.Txid)) == 0 {
				levels[j][i] = tree.Node{
					Txid:       node.Txid,
					Tx:         node.Tx,
					ParentTxid: node.ParentTxid,
					Leaf:       true,
				}
			}
		}
	}

	return levels
}
