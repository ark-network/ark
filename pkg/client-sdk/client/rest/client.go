package restclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/client/rest/service/arkservice"
	"github.com/ark-network/ark/pkg/client-sdk/client/rest/service/arkservice/ark_service"
	"github.com/ark-network/ark/pkg/client-sdk/client/rest/service/models"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

type restClient struct {
	svc            ark_service.ClientService
	eventsCh       chan client.RoundEventChannel
	requestTimeout time.Duration
	treeCache      *utils.Cache[tree.CongestionTree]
}

func NewClient(aspUrl string) (client.ASPClient, error) {
	if len(aspUrl) <= 0 {
		return nil, fmt.Errorf("missing asp url")
	}
	svc, err := newRestClient(aspUrl)
	if err != nil {
		return nil, err
	}
	eventsCh := make(chan client.RoundEventChannel)
	reqTimeout := 15 * time.Second
	treeCache := utils.NewCache[tree.CongestionTree]()

	return &restClient{svc, eventsCh, reqTimeout, treeCache}, nil
}

func (c *restClient) Close() {}

func (a *restClient) GetEventStream(
	ctx context.Context, paymentID string,
) (<-chan client.RoundEventChannel, error) {
	go func(payID string) {
		defer close(a.eventsCh)

		timeout := time.After(a.requestTimeout)

		for {
			select {
			case <-timeout:
				a.eventsCh <- client.RoundEventChannel{
					Err: fmt.Errorf("timeout reached"),
				}
				return
			default:
				event, err := a.Ping(ctx, payID)
				if err != nil {
					a.eventsCh <- client.RoundEventChannel{
						Err: err,
					}
					return
				}

				if event != nil {
					a.eventsCh <- client.RoundEventChannel{
						Event: event,
					}
				}

				time.Sleep(1 * time.Second)
			}
		}
	}(paymentID)

	return a.eventsCh, nil
}

func (a *restClient) GetInfo(
	ctx context.Context,
) (*client.Info, error) {
	resp, err := a.svc.ArkServiceGetInfo(ark_service.NewArkServiceGetInfoParams())
	if err != nil {
		return nil, err
	}

	roundLifetime, err := strconv.Atoi(resp.Payload.RoundLifetime)
	if err != nil {
		return nil, err
	}

	unilateralExitDelay, err := strconv.Atoi(resp.Payload.UnilateralExitDelay)
	if err != nil {
		return nil, err
	}

	roundInterval, err := strconv.Atoi(resp.Payload.RoundInterval)
	if err != nil {
		return nil, err
	}

	minRelayFee, err := strconv.Atoi(resp.Payload.MinRelayFee)
	if err != nil {
		return nil, err
	}

	return &client.Info{
		Pubkey:                     resp.Payload.Pubkey,
		RoundLifetime:              int64(roundLifetime),
		UnilateralExitDelay:        int64(unilateralExitDelay),
		RoundInterval:              int64(roundInterval),
		Network:                    resp.Payload.Network,
		MinRelayFee:                int64(minRelayFee),
		BoardingDescriptorTemplate: resp.Payload.BoardingDescriptorTemplate,
	}, nil
}

func (a *restClient) ListVtxos(
	ctx context.Context, addr string,
) ([]client.Vtxo, []client.Vtxo, error) {
	resp, err := a.svc.ArkServiceListVtxos(
		ark_service.NewArkServiceListVtxosParams().WithAddress(addr),
	)
	if err != nil {
		return nil, nil, err
	}

	spendableVtxos := make([]client.Vtxo, 0, len(resp.Payload.SpendableVtxos))
	for _, v := range resp.Payload.SpendableVtxos {
		var expiresAt *time.Time
		if v.ExpireAt != "" && v.ExpireAt != "0" {
			expAt, err := strconv.Atoi(v.ExpireAt)
			if err != nil {
				return nil, nil, err
			}
			t := time.Unix(int64(expAt), 0)
			expiresAt = &t
		}

		amount, err := strconv.Atoi(v.Receiver.Amount)
		if err != nil {
			return nil, nil, err
		}

		var redeemTx string
		var uncondForfeitTxs []string
		if v.PendingData != nil {
			redeemTx = v.PendingData.RedeemTx
			uncondForfeitTxs = v.PendingData.UnconditionalForfeitTxs
		}

		spendableVtxos = append(spendableVtxos, client.Vtxo{
			VtxoKey: client.VtxoKey{
				Txid: v.Outpoint.VtxoInput.Txid,
				VOut: uint32(v.Outpoint.VtxoInput.Vout),
			},
			Amount:                  uint64(amount),
			RoundTxid:               v.PoolTxid,
			ExpiresAt:               expiresAt,
			Pending:                 v.Pending,
			RedeemTx:                redeemTx,
			UnconditionalForfeitTxs: uncondForfeitTxs,
		})
	}

	spentVtxos := make([]client.Vtxo, 0, len(resp.Payload.SpentVtxos))
	for _, v := range resp.Payload.SpentVtxos {
		var expiresAt *time.Time
		if v.ExpireAt != "" && v.ExpireAt != "0" {
			expAt, err := strconv.Atoi(v.ExpireAt)
			if err != nil {
				return nil, nil, err
			}
			t := time.Unix(int64(expAt), 0)
			expiresAt = &t
		}

		amount, err := strconv.Atoi(v.Receiver.Amount)
		if err != nil {
			return nil, nil, err
		}

		spentVtxos = append(spentVtxos, client.Vtxo{
			VtxoKey: client.VtxoKey{
				Txid: v.Outpoint.VtxoInput.Txid,
				VOut: uint32(v.Outpoint.VtxoInput.Vout),
			},
			Amount:    uint64(amount),
			RoundTxid: v.PoolTxid,
			ExpiresAt: expiresAt,
		})
	}

	return spendableVtxos, spentVtxos, nil
}

func (a *restClient) GetRound(
	ctx context.Context, txID string,
) (*client.Round, error) {
	resp, err := a.svc.ArkServiceGetRound(
		ark_service.NewArkServiceGetRoundParams().WithTxid(txID),
	)
	if err != nil {
		return nil, err
	}

	start, err := strconv.Atoi(resp.Payload.Round.Start)
	if err != nil {
		return nil, err
	}

	end, err := strconv.Atoi(resp.Payload.Round.End)
	if err != nil {
		return nil, err
	}

	startedAt := time.Unix(int64(start), 0)
	var endedAt *time.Time
	if end > 0 {
		t := time.Unix(int64(end), 0)
		endedAt = &t
	}

	return &client.Round{
		ID:         resp.Payload.Round.ID,
		StartedAt:  &startedAt,
		EndedAt:    endedAt,
		Tx:         resp.Payload.Round.PoolTx,
		Tree:       treeFromProto{resp.Payload.Round.CongestionTree}.parse(),
		ForfeitTxs: resp.Payload.Round.ForfeitTxs,
		Connectors: resp.Payload.Round.Connectors,
		Stage:      toRoundStage(*resp.Payload.Round.Stage),
	}, nil
}

func (a *restClient) RegisterPayment(
	ctx context.Context, inputs []client.Input, ephemeralPublicKey string,
) (string, error) {
	ins := make([]*models.V1Input, 0, len(inputs))
	for _, i := range inputs {
		var input *models.V1Input

		if len(i.GetDescriptor()) > 0 {
			input = &models.V1Input{
				BoardingInput: &models.V1BoardingInput{
					Txid:       i.GetTxID(),
					Vout:       int64(i.GetVOut()),
					Descriptor: i.GetDescriptor(),
				},
			}
		} else {
			input = &models.V1Input{
				VtxoInput: &models.V1VtxoInput{
					Txid: i.GetTxID(),
					Vout: int64(i.GetVOut()),
				},
			}
		}

		ins = append(ins, input)
	}
	body := &models.V1RegisterPaymentRequest{
		Inputs: ins,
	}
	if len(ephemeralPublicKey) > 0 {
		body.EphemeralPubkey = ephemeralPublicKey
	}

	resp, err := a.svc.ArkServiceRegisterPayment(
		ark_service.NewArkServiceRegisterPaymentParams().WithBody(body),
	)
	if err != nil {
		return "", err
	}

	return resp.Payload.ID, nil
}

func (a *restClient) ClaimPayment(
	ctx context.Context, paymentID string, outputs []client.Output,
) error {
	outs := make([]*models.V1Output, 0, len(outputs))
	for _, o := range outputs {
		outs = append(outs, &models.V1Output{
			Address: o.Address,
			Amount:  strconv.Itoa(int(o.Amount)),
		})
	}
	body := models.V1ClaimPaymentRequest{
		ID:      paymentID,
		Outputs: outs,
	}

	_, err := a.svc.ArkServiceClaimPayment(
		ark_service.NewArkServiceClaimPaymentParams().WithBody(&body),
	)
	return err
}

func (a *restClient) Ping(
	ctx context.Context, paymentID string,
) (client.RoundEvent, error) {
	r := ark_service.NewArkServicePingParams()
	r.SetPaymentID(paymentID)
	resp, err := a.svc.ArkServicePing(r)
	if err != nil {
		return nil, err
	}

	payload := resp.Payload

	if e := payload.RoundFailed; e != nil {
		return client.RoundFailedEvent{
			ID:     e.ID,
			Reason: e.Reason,
		}, nil
	}
	if e := payload.RoundFinalization; e != nil {
		tree := treeFromProto{e.CongestionTree}.parse()
		return client.RoundFinalizationEvent{
			ID:         e.ID,
			Tx:         e.PoolTx,
			ForfeitTxs: e.ForfeitTxs,
			Tree:       tree,
			Connectors: e.Connectors,
		}, nil
	}

	if e := payload.RoundFinalized; e != nil {
		return client.RoundFinalizedEvent{
			ID:   e.ID,
			Txid: e.PoolTxid,
		}, nil
	}

	if e := payload.RoundSigning; e != nil {
		pubkeys := make([]*secp256k1.PublicKey, 0, len(e.CosignersPubkeys))
		for _, pubkey := range e.CosignersPubkeys {
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
			ID:                  e.ID,
			UnsignedTree:        treeFromProto{e.UnsignedTree}.parse(),
			CosignersPublicKeys: pubkeys,
		}, nil
	}

	if e := payload.RoundSigningNoncesGenerated; e != nil {
		nonces, err := bitcointree.DecodeNonces(hex.NewDecoder(strings.NewReader(e.TreeNonces)))
		if err != nil {
			return nil, err
		}
		return client.RoundSigningNoncesGeneratedEvent{
			ID:     e.ID,
			Nonces: nonces,
		}, nil
	}

	return nil, nil
}

func (a *restClient) FinalizePayment(
	ctx context.Context, signedForfeitTxs []string, signedRoundTx string,
) error {
	body := models.V1FinalizePaymentRequest{
		SignedForfeitTxs: signedForfeitTxs,
		SignedRoundTx:    signedRoundTx,
	}
	_, err := a.svc.ArkServiceFinalizePayment(
		ark_service.NewArkServiceFinalizePaymentParams().WithBody(&body),
	)
	return err
}

func (a *restClient) CreatePayment(
	ctx context.Context, inputs []client.VtxoKey, outputs []client.Output,
) (string, []string, error) {
	ins := make([]*models.V1Input, 0, len(inputs))
	for _, i := range inputs {
		if len(i.GetDescriptor()) > 0 {
			return "", nil, fmt.Errorf("boarding inputs are not allowed in create payment")
		}

		ins = append(ins, &models.V1Input{
			VtxoInput: &models.V1VtxoInput{
				Txid: i.Txid,
				Vout: int64(i.VOut),
			},
		})
	}
	outs := make([]*models.V1Output, 0, len(outputs))
	for _, o := range outputs {
		outs = append(outs, &models.V1Output{
			Address: o.Address,
			Amount:  strconv.Itoa(int(o.Amount)),
		})
	}
	body := models.V1CreatePaymentRequest{
		Inputs:  ins,
		Outputs: outs,
	}
	resp, err := a.svc.ArkServiceCreatePayment(
		ark_service.NewArkServiceCreatePaymentParams().WithBody(&body),
	)
	if err != nil {
		return "", nil, err
	}
	return resp.GetPayload().SignedRedeemTx, resp.GetPayload().UsignedUnconditionalForfeitTxs, nil
}

func (a *restClient) CompletePayment(
	ctx context.Context, signedRedeemTx string, signedUnconditionalForfeitTxs []string,
) error {
	req := &arkv1.CompletePaymentRequest{
		SignedRedeemTx:                signedRedeemTx,
		SignedUnconditionalForfeitTxs: signedUnconditionalForfeitTxs,
	}
	body := models.V1CompletePaymentRequest{
		SignedRedeemTx:                req.GetSignedRedeemTx(),
		SignedUnconditionalForfeitTxs: req.GetSignedUnconditionalForfeitTxs(),
	}
	_, err := a.svc.ArkServiceCompletePayment(
		ark_service.NewArkServiceCompletePaymentParams().WithBody(&body),
	)
	return err
}

func (a *restClient) GetRoundByID(
	ctx context.Context, roundID string,
) (*client.Round, error) {
	resp, err := a.svc.ArkServiceGetRoundByID(
		ark_service.NewArkServiceGetRoundByIDParams().WithID(roundID),
	)
	if err != nil {
		return nil, err
	}

	start, err := strconv.Atoi(resp.Payload.Round.Start)
	if err != nil {
		return nil, err
	}

	end, err := strconv.Atoi(resp.Payload.Round.End)
	if err != nil {
		return nil, err
	}

	startedAt := time.Unix(int64(start), 0)
	var endedAt *time.Time
	if end > 0 {
		t := time.Unix(int64(end), 0)
		endedAt = &t
	}

	return &client.Round{
		ID:         resp.Payload.Round.ID,
		StartedAt:  &startedAt,
		EndedAt:    endedAt,
		Tx:         resp.Payload.Round.PoolTx,
		Tree:       treeFromProto{resp.Payload.Round.CongestionTree}.parse(),
		ForfeitTxs: resp.Payload.Round.ForfeitTxs,
		Connectors: resp.Payload.Round.Connectors,
		Stage:      toRoundStage(*resp.Payload.Round.Stage),
	}, nil
}

func (a *restClient) GetBoardingAddress(
	ctx context.Context, pubkey string,
) (string, error) {
	body := models.V1GetBoardingAddressRequest{
		Pubkey: pubkey,
	}

	resp, err := a.svc.ArkServiceGetBoardingAddress(
		ark_service.NewArkServiceGetBoardingAddressParams().WithBody(&body),
	)
	if err != nil {
		return "",
			err
	}
	return resp.Payload.Address, nil
}

func (a *restClient) SendTreeNonces(
	ctx context.Context, roundID, cosignerPubkey string, nonces bitcointree.TreeNonces,
) error {
	var nonceBuffer bytes.Buffer

	if err := nonces.Encode(&nonceBuffer); err != nil {
		return err
	}

	serializedNonces := hex.EncodeToString(nonceBuffer.Bytes())

	body := &models.V1SendTreeNoncesRequest{
		RoundID:    roundID,
		PublicKey:  cosignerPubkey,
		TreeNonces: serializedNonces,
	}

	if _, err := a.svc.ArkServiceSendTreeNonces(
		ark_service.NewArkServiceSendTreeNoncesParams().WithBody(body),
	); err != nil {
		return err
	}

	return nil
}

func (a *restClient) SendTreeSignatures(
	ctx context.Context, roundID, cosignerPubkey string, signatures bitcointree.TreePartialSigs,
) error {
	var sigsBuffer bytes.Buffer

	if err := signatures.Encode(&sigsBuffer); err != nil {
		return err
	}

	serializedSigs := hex.EncodeToString(sigsBuffer.Bytes())

	body := &models.V1SendTreeSignaturesRequest{
		RoundID:        roundID,
		PublicKey:      cosignerPubkey,
		TreeSignatures: serializedSigs,
	}

	if _, err := a.svc.ArkServiceSendTreeSignatures(
		ark_service.NewArkServiceSendTreeSignaturesParams().WithBody(body),
	); err != nil {
		return err
	}

	return nil
}

func newRestClient(
	serviceURL string,
) (ark_service.ClientService, error) {
	parsedURL, err := url.Parse(serviceURL)
	if err != nil {
		return nil, err
	}

	schemes := []string{parsedURL.Scheme}
	host := parsedURL.Host
	basePath := parsedURL.Path

	if basePath == "" {
		basePath = arkservice.DefaultBasePath
	}

	cfg := &arkservice.TransportConfig{
		Host:     host,
		BasePath: basePath,
		Schemes:  schemes,
	}

	transport := httptransport.New(cfg.Host, cfg.BasePath, cfg.Schemes)
	svc := arkservice.New(transport, strfmt.Default)
	return svc.ArkService, nil
}

func toRoundStage(stage models.V1RoundStage) client.RoundStage {
	switch stage {
	case models.V1RoundStageROUNDSTAGEREGISTRATION:
		return client.RoundStageRegistration
	case models.V1RoundStageROUNDSTAGEFINALIZATION:
		return client.RoundStageFinalization
	case models.V1RoundStageROUNDSTAGEFINALIZED:
		return client.RoundStageFinalized
	case models.V1RoundStageROUNDSTAGEFAILED:
		return client.RoundStageFailed
	default:
		return client.RoundStageUndefined
	}
}

type treeFromProto struct {
	*models.V1Tree
}

func (t treeFromProto) parse() tree.CongestionTree {
	congestionTree := make(tree.CongestionTree, 0, len(t.Levels))
	for _, l := range t.Levels {
		level := make([]tree.Node, 0, len(l.Nodes))
		for _, n := range l.Nodes {
			level = append(level, tree.Node{
				Txid:       n.Txid,
				Tx:         n.Tx,
				ParentTxid: n.ParentTxid,
			})
		}
		congestionTree = append(congestionTree, level)
	}

	for j, treeLvl := range congestionTree {
		for i, node := range treeLvl {
			if len(congestionTree.Children(node.Txid)) == 0 {
				congestionTree[j][i] = tree.Node{
					Txid:       node.Txid,
					Tx:         node.Tx,
					ParentTxid: node.ParentTxid,
					Leaf:       true,
				}
			}
		}
	}

	return congestionTree
}
