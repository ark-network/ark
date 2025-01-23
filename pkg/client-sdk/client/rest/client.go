package restclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/client/rest/service/arkservice"
	"github.com/ark-network/ark/pkg/client-sdk/client/rest/service/arkservice/ark_service"
	"github.com/ark-network/ark/pkg/client-sdk/client/rest/service/explorerservice"
	"github.com/ark-network/ark/pkg/client-sdk/client/rest/service/explorerservice/explorer_service"
	"github.com/ark-network/ark/pkg/client-sdk/client/rest/service/models"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	log "github.com/sirupsen/logrus"
)

type restClient struct {
	serverURL      string
	svc            ark_service.ClientService
	explorerSvc    explorer_service.ClientService
	requestTimeout time.Duration
	treeCache      *utils.Cache[tree.VtxoTree]
}

func NewClient(serverURL string) (client.TransportClient, error) {
	if len(serverURL) <= 0 {
		return nil, fmt.Errorf("missing server url")
	}
	svc, err := newRestArkClient(serverURL)
	if err != nil {
		return nil, err
	}
	explorerSvc, err := newRestExplorerClient(serverURL)
	if err != nil {
		return nil, err
	}
	// TODO: use twice the round interval.
	reqTimeout := 15 * time.Second
	treeCache := utils.NewCache[tree.VtxoTree]()

	return &restClient{serverURL, svc, explorerSvc, reqTimeout, treeCache}, nil
}

func (a *restClient) GetInfo(
	ctx context.Context,
) (*client.Info, error) {
	resp, err := a.svc.ArkServiceGetInfo(ark_service.NewArkServiceGetInfoParams())
	if err != nil {
		return nil, err
	}

	vtxoTreeExpiry, err := strconv.Atoi(resp.Payload.VtxoTreeExpiry)
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

	dust, err := strconv.Atoi(resp.Payload.Dust)
	if err != nil {
		return nil, err
	}

	return &client.Info{
		PubKey:                     resp.Payload.Pubkey,
		VtxoTreeExpiry:             int64(vtxoTreeExpiry),
		UnilateralExitDelay:        int64(unilateralExitDelay),
		RoundInterval:              int64(roundInterval),
		Network:                    resp.Payload.Network,
		Dust:                       uint64(dust),
		BoardingDescriptorTemplate: resp.Payload.BoardingDescriptorTemplate,
		ForfeitAddress:             resp.Payload.ForfeitAddress,
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

func (a *restClient) RegisterInputsForNextRound(
	ctx context.Context, inputs []client.Input, ephemeralPubkey string,
) (string, error) {
	ins := make([]*models.V1Input, 0, len(inputs))
	for _, i := range inputs {
		ins = append(ins, &models.V1Input{
			Outpoint: &models.V1Outpoint{
				Txid: i.Txid,
				Vout: int64(i.VOut),
			},
			Tapscripts: &models.V1Tapscripts{
				Scripts: i.Tapscripts,
			},
		})
	}
	body := &models.V1RegisterInputsForNextRoundRequest{
		Inputs: ins,
	}
	if len(ephemeralPubkey) > 0 {
		body.EphemeralPubkey = ephemeralPubkey
	}

	resp, err := a.svc.ArkServiceRegisterInputsForNextRound(
		ark_service.NewArkServiceRegisterInputsForNextRoundParams().WithBody(body),
	)
	if err != nil {
		return "", err
	}

	return resp.Payload.RequestID, nil
}

func (a *restClient) RegisterNotesForNextRound(
	ctx context.Context, notes []string, ephemeralKey string,
) (string, error) {
	body := &models.V1RegisterInputsForNextRoundRequest{
		Notes: notes,
	}
	if len(ephemeralKey) > 0 {
		body.EphemeralPubkey = ephemeralKey
	}
	resp, err := a.svc.ArkServiceRegisterInputsForNextRound(
		ark_service.NewArkServiceRegisterInputsForNextRoundParams().WithBody(body),
	)
	if err != nil {
		return "", err
	}
	return resp.Payload.RequestID, nil
}

func (a *restClient) RegisterOutputsForNextRound(
	ctx context.Context, requestID string, outputs []client.Output,
) error {
	outs := make([]*models.V1Output, 0, len(outputs))
	for _, o := range outputs {
		outs = append(outs, &models.V1Output{
			Address: o.Address,
			Amount:  strconv.Itoa(int(o.Amount)),
		})
	}
	body := models.V1RegisterOutputsForNextRoundRequest{
		RequestID: requestID,
		Outputs:   outs,
	}

	_, err := a.svc.ArkServiceRegisterOutputsForNextRound(
		ark_service.NewArkServiceRegisterOutputsForNextRoundParams().WithBody(&body),
	)
	return err
}

func (a *restClient) SubmitTreeNonces(
	ctx context.Context, roundID, cosignerPubkey string,
	nonces bitcointree.TreeNonces,
) error {
	var nonceBuffer bytes.Buffer

	if err := nonces.Encode(&nonceBuffer); err != nil {
		return err
	}

	serializedNonces := hex.EncodeToString(nonceBuffer.Bytes())

	body := &models.V1SubmitTreeNoncesRequest{
		RoundID:    roundID,
		Pubkey:     cosignerPubkey,
		TreeNonces: serializedNonces,
	}

	if _, err := a.svc.ArkServiceSubmitTreeNonces(
		ark_service.NewArkServiceSubmitTreeNoncesParams().WithBody(body),
	); err != nil {
		return err
	}

	return nil
}

func (a *restClient) SubmitTreeSignatures(
	ctx context.Context, roundID, cosignerPubkey string,
	signatures bitcointree.TreePartialSigs,
) error {
	var sigsBuffer bytes.Buffer

	if err := signatures.Encode(&sigsBuffer); err != nil {
		return err
	}

	serializedSigs := hex.EncodeToString(sigsBuffer.Bytes())

	body := &models.V1SubmitTreeSignaturesRequest{
		RoundID:        roundID,
		Pubkey:         cosignerPubkey,
		TreeSignatures: serializedSigs,
	}

	if _, err := a.svc.ArkServiceSubmitTreeSignatures(
		ark_service.NewArkServiceSubmitTreeSignaturesParams().WithBody(body),
	); err != nil {
		return err
	}

	return nil
}

func (a *restClient) SubmitSignedForfeitTxs(
	ctx context.Context, signedForfeitTxs []string, signedRoundTx string,
) error {
	body := models.V1SubmitSignedForfeitTxsRequest{
		SignedForfeitTxs: signedForfeitTxs,
		SignedRoundTx:    signedRoundTx,
	}
	_, err := a.svc.ArkServiceSubmitSignedForfeitTxs(
		ark_service.NewArkServiceSubmitSignedForfeitTxsParams().WithBody(&body),
	)
	return err
}

func (c *restClient) GetEventStream(
	ctx context.Context, requestID string,
) (<-chan client.RoundEventChannel, func(), error) {
	eventsCh := make(chan client.RoundEventChannel)

	go func(eventsCh chan client.RoundEventChannel) {
		httpClient := &http.Client{Timeout: time.Second * 0}

		resp, err := httpClient.Get(fmt.Sprintf("%s/v1/events", c.serverURL))
		if err != nil {
			eventsCh <- client.RoundEventChannel{
				Err: fmt.Errorf("failed to fetch round event stream: %s", err),
			}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			eventsCh <- client.RoundEventChannel{
				Err: fmt.Errorf("received unexpected status %d code when fetching round event stream", resp.StatusCode),
			}
			return
		}

		reader := bufio.NewReader(resp.Body)

		for {
			chunk, err := reader.ReadBytes('\n')
			if err != nil {
				// Stream ended
				if err == io.EOF {
					return
				}
				log.WithError(err).Warn("failed to read from round event stream")
				return
			}

			chunk = bytes.Trim(chunk, "\n")
			resp := ark_service.ArkServiceGetEventStreamOKBody{}
			if err := json.Unmarshal(chunk, &resp); err != nil {
				eventsCh <- client.RoundEventChannel{
					Err: fmt.Errorf("failed to parse message from round event stream: %s", err),
				}
				return
			}

			emptyResp := ark_service.ArkServiceGetEventStreamOKBody{}
			if resp == emptyResp {
				continue
			}

			if resp.Error != nil {
				eventsCh <- client.RoundEventChannel{
					Err: fmt.Errorf("received error %d: %s", resp.Error.Code, resp.Error.Message),
				}
				continue
			}

			// Handle different event types
			var event client.RoundEvent
			var _err error
			switch {
			case resp.Result.RoundFailed != nil:
				e := resp.Result.RoundFailed
				event = client.RoundFailedEvent{
					ID:     e.ID,
					Reason: e.Reason,
				}
			case resp.Result.RoundFinalization != nil:
				e := resp.Result.RoundFinalization
				tree := treeFromProto{e.VtxoTree}.parse()

				minRelayFeeRate, err := strconv.Atoi(e.MinRelayFeeRate)
				if err != nil {
					_err = err
					break
				}

				event = client.RoundFinalizationEvent{
					ID:              e.ID,
					Tx:              e.RoundTx,
					Tree:            tree,
					Connectors:      e.Connectors,
					MinRelayFeeRate: chainfee.SatPerKVByte(minRelayFeeRate),
				}
			case resp.Result.RoundFinalized != nil:
				e := resp.Result.RoundFinalized
				event = client.RoundFinalizedEvent{
					ID:   e.ID,
					Txid: e.RoundTxid,
				}
			case resp.Result.RoundSigning != nil:
				e := resp.Result.RoundSigning
				pubkeys := make([]*secp256k1.PublicKey, 0, len(e.CosignersPubkeys))
				for _, pubkey := range e.CosignersPubkeys {
					p, err := hex.DecodeString(pubkey)
					if err != nil {
						_err = err
						break
					}
					pk, err := secp256k1.ParsePubKey(p)
					if err != nil {
						_err = err
						break
					}
					pubkeys = append(pubkeys, pk)
				}

				event = client.RoundSigningStartedEvent{
					ID:               e.ID,
					UnsignedTree:     treeFromProto{e.UnsignedVtxoTree}.parse(),
					CosignersPubKeys: pubkeys,
					UnsignedRoundTx:  e.UnsignedRoundTx,
				}
			case resp.Result.RoundSigningNoncesGenerated != nil:
				e := resp.Result.RoundSigningNoncesGenerated
				reader := hex.NewDecoder(strings.NewReader(e.TreeNonces))
				nonces, err := bitcointree.DecodeNonces(reader)
				if err != nil {
					_err = err
					break
				}
				event = client.RoundSigningNoncesGeneratedEvent{
					ID:     e.ID,
					Nonces: nonces,
				}
			}

			eventsCh <- client.RoundEventChannel{
				Event: event,
				Err:   _err,
			}
		}
	}(eventsCh)

	return eventsCh, func() {}, nil
}

func (a *restClient) Ping(
	ctx context.Context, requestID string,
) error {
	r := ark_service.NewArkServicePingParams()
	r.SetRequestID(requestID)
	_, err := a.svc.ArkServicePing(r)
	return err
}

func (a *restClient) SubmitRedeemTx(
	ctx context.Context, redeemTx string,
) (string, error) {
	req := &models.V1SubmitRedeemTxRequest{
		RedeemTx: redeemTx,
	}
	resp, err := a.svc.ArkServiceSubmitRedeemTx(
		ark_service.NewArkServiceSubmitRedeemTxParams().WithBody(req),
	)
	if err != nil {
		return "", err
	}
	return resp.Payload.SignedRedeemTx, nil
}

func (a *restClient) GetRound(
	ctx context.Context, txID string,
) (*client.Round, error) {
	resp, err := a.explorerSvc.ExplorerServiceGetRound(
		explorer_service.NewExplorerServiceGetRoundParams().WithTxid(txID),
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
		Tx:         resp.Payload.Round.RoundTx,
		Tree:       treeFromProto{resp.Payload.Round.VtxoTree}.parse(),
		ForfeitTxs: resp.Payload.Round.ForfeitTxs,
		Connectors: resp.Payload.Round.Connectors,
		Stage:      toRoundStage(*resp.Payload.Round.Stage),
	}, nil
}

func (a *restClient) GetRoundByID(
	ctx context.Context, roundID string,
) (*client.Round, error) {
	resp, err := a.explorerSvc.ExplorerServiceGetRoundByID(
		explorer_service.NewExplorerServiceGetRoundByIDParams().WithID(roundID),
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
		Tx:         resp.Payload.Round.RoundTx,
		Tree:       treeFromProto{resp.Payload.Round.VtxoTree}.parse(),
		ForfeitTxs: resp.Payload.Round.ForfeitTxs,
		Connectors: resp.Payload.Round.Connectors,
		Stage:      toRoundStage(*resp.Payload.Round.Stage),
	}, nil
}

func (a *restClient) ListVtxos(
	ctx context.Context, addr string,
) ([]client.Vtxo, []client.Vtxo, error) {
	resp, err := a.explorerSvc.ExplorerServiceListVtxos(
		explorer_service.NewExplorerServiceListVtxosParams().WithAddress(addr),
	)
	if err != nil {
		return nil, nil, err
	}

	spendableVtxos := vtxosFromRest(resp.Payload.SpendableVtxos)
	spentVtxos := vtxosFromRest(resp.Payload.SpentVtxos)

	return spendableVtxos, spentVtxos, nil
}

func (a *restClient) SetNostrRecipient(
	ctx context.Context, nostrRecipient string, vtxos []client.SignedVtxoOutpoint,
) error {
	body := models.V1SetNostrRecipientRequest{
		NostrRecipient: nostrRecipient,
		Vtxos:          toSignedVtxoModel(vtxos),
	}

	_, err := a.svc.ArkServiceSetNostrRecipient(
		ark_service.NewArkServiceSetNostrRecipientParams().WithBody(&body),
	)
	return err
}

func (a *restClient) DeleteNostrRecipient(
	ctx context.Context, vtxos []client.SignedVtxoOutpoint,
) error {
	body := models.V1DeleteNostrRecipientRequest{
		Vtxos: toSignedVtxoModel(vtxos),
	}

	_, err := a.svc.ArkServiceDeleteNostrRecipient(
		ark_service.NewArkServiceDeleteNostrRecipientParams().WithBody(&body),
	)
	return err
}

func (c *restClient) Close() {}

func newRestArkClient(
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

func newRestExplorerClient(
	serviceURL string,
) (explorer_service.ClientService, error) {
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

	cfg := &explorerservice.TransportConfig{
		Host:     host,
		BasePath: basePath,
		Schemes:  schemes,
	}

	transport := httptransport.New(cfg.Host, cfg.BasePath, cfg.Schemes)
	svc := explorerservice.New(transport, strfmt.Default)
	return svc.ExplorerService, nil
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

func (t treeFromProto) parse() tree.VtxoTree {
	vtxoTree := make(tree.VtxoTree, 0, len(t.Levels))
	for _, l := range t.Levels {
		level := make([]tree.Node, 0, len(l.Nodes))
		for _, n := range l.Nodes {
			level = append(level, tree.Node{
				Txid:       n.Txid,
				Tx:         n.Tx,
				ParentTxid: n.ParentTxid,
			})
		}
		vtxoTree = append(vtxoTree, level)
	}

	for j, treeLvl := range vtxoTree {
		for i, node := range treeLvl {
			if len(vtxoTree.Children(node.Txid)) == 0 {
				vtxoTree[j][i] = tree.Node{
					Txid:       node.Txid,
					Tx:         node.Tx,
					ParentTxid: node.ParentTxid,
					Leaf:       true,
				}
			}
		}
	}

	return vtxoTree
}

func (c *restClient) GetTransactionsStream(ctx context.Context) (<-chan client.TransactionEvent, func(), error) {
	eventsCh := make(chan client.TransactionEvent)

	go func(eventsCh chan client.TransactionEvent) {
		httpClient := &http.Client{Timeout: time.Second * 0}

		resp, err := httpClient.Get(fmt.Sprintf("%s/v1/transactions", c.serverURL))
		if err != nil {
			eventsCh <- client.TransactionEvent{Err: err}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			eventsCh <- client.TransactionEvent{
				Err: fmt.Errorf("unexpected status code: %d", resp.StatusCode),
			}
			return
		}

		reader := bufio.NewReader(resp.Body)
		for {
			chunk, err := reader.ReadBytes('\n')
			if err != nil {
				// Stream ended
				if err == io.EOF {
					return
				}
				eventsCh <- client.TransactionEvent{
					Err: fmt.Errorf("failed to read from transaction stream: %s", err),
				}
				return
			}

			chunk = bytes.Trim(chunk, "\n")
			resp := ark_service.ArkServiceGetTransactionsStreamOK{}
			if err := json.Unmarshal(chunk, &resp); err != nil {
				eventsCh <- client.TransactionEvent{
					Err: fmt.Errorf("failed to parse message from transaction stream: %s", err),
				}
				return
			}

			if resp.Payload == nil {
				continue
			}

			if resp.Payload.Error != nil {
				eventsCh <- client.TransactionEvent{
					Err: fmt.Errorf("received error from transaction stream: %s", resp.Payload.Error.Message),
				}
				continue
			}

			var event client.TransactionEvent
			if resp.Payload.Result.Round != nil {
				event = client.TransactionEvent{
					Round: &client.RoundTransaction{
						Txid:                 resp.Payload.Result.Round.Txid,
						SpentVtxos:           outpointsFromRest(resp.Payload.Result.Round.SpentVtxos),
						SpendableVtxos:       vtxosFromRest(resp.Payload.Result.Round.SpendableVtxos),
						ClaimedBoardingUtxos: outpointsFromRest(resp.Payload.Result.Round.ClaimedBoardingUtxos),
					},
				}
			} else if resp.Payload.Result.Redeem != nil {
				event = client.TransactionEvent{
					Redeem: &client.RedeemTransaction{
						Txid:           resp.Payload.Result.Redeem.Txid,
						SpentVtxos:     outpointsFromRest(resp.Payload.Result.Redeem.SpentVtxos),
						SpendableVtxos: vtxosFromRest(resp.Payload.Result.Redeem.SpendableVtxos),
					},
				}
			}

			eventsCh <- event
		}
	}(eventsCh)

	return eventsCh, func() {}, nil
}

func outpointsFromRest(restOutpoints []*models.V1Outpoint) []client.Outpoint {
	outpoints := make([]client.Outpoint, len(restOutpoints))
	for i, o := range restOutpoints {
		outpoints[i] = client.Outpoint{
			Txid: o.Txid,
			VOut: uint32(o.Vout),
		}
	}
	return outpoints
}

func vtxosFromRest(restVtxos []*models.V1Vtxo) []client.Vtxo {
	vtxos := make([]client.Vtxo, len(restVtxos))
	for i, v := range restVtxos {
		var expiresAt, createdAt time.Time
		if v.ExpireAt != "" && v.ExpireAt != "0" {
			expAt, err := strconv.Atoi(v.ExpireAt)
			if err != nil {
				return nil
			}
			expiresAt = time.Unix(int64(expAt), 0)
		}

		if v.CreatedAt != "" && v.CreatedAt != "0" {
			creaAt, err := strconv.Atoi(v.CreatedAt)
			if err != nil {
				return nil
			}
			createdAt = time.Unix(int64(creaAt), 0)
		}

		amount, err := strconv.Atoi(v.Amount)
		if err != nil {
			return nil
		}

		vtxos[i] = client.Vtxo{
			Outpoint: client.Outpoint{
				Txid: v.Outpoint.Txid,
				VOut: uint32(v.Outpoint.Vout),
			},
			PubKey:    v.Pubkey,
			Amount:    uint64(amount),
			RoundTxid: v.RoundTxid,
			ExpiresAt: expiresAt,
			RedeemTx:  v.RedeemTx,
			IsPending: v.IsPending,
			SpentBy:   v.SpentBy,
			CreatedAt: createdAt,
		}
	}
	return vtxos
}

func toSignedVtxoModel(vtxos []client.SignedVtxoOutpoint) []*models.V1SignedVtxoOutpoint {
	signedVtxos := make([]*models.V1SignedVtxoOutpoint, 0, len(vtxos))
	for _, v := range vtxos {
		signedVtxos = append(signedVtxos, &models.V1SignedVtxoOutpoint{
			Outpoint: &models.V1Outpoint{
				Txid: v.Outpoint.Txid,
				Vout: int64(v.Outpoint.VOut),
			},
			Proof: &models.V1OwnershipProof{
				ControlBlock: v.Proof.ControlBlock,
				Script:       v.Proof.Script,
				Signature:    v.Proof.Signature,
			},
		})
	}
	return signedVtxos
}
