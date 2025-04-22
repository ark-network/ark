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
	"github.com/ark-network/ark/pkg/client-sdk/client/rest/service/indexerservice"
	"github.com/ark-network/ark/pkg/client-sdk/client/rest/service/indexerservice/indexer_service"
	"github.com/ark-network/ark/pkg/client-sdk/client/rest/service/models"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// restClient implements the TransportClient interface for REST communication
type restClient struct {
	serverURL      string
	svc            ark_service.ClientService
	explorerSvc    explorer_service.ClientService
	indexerSvc     indexer_service.ClientService
	requestTimeout time.Duration
	treeCache      *utils.Cache[tree.TxTree]
}

// NewClient creates a new REST client for the Ark service
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
	indexerSvc, err := newRestIndexerClient(serverURL)
	if err != nil {
		return nil, err
	}
	// TODO: use twice the round interval.
	reqTimeout := 15 * time.Second
	treeCache := utils.NewCache[tree.TxTree]()

	return &restClient{serverURL, svc, explorerSvc, indexerSvc, reqTimeout, treeCache}, nil
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
	nextStartTime, err := strconv.Atoi(resp.Payload.MarketHour.NextStartTime)
	if err != nil {
		return nil, err
	}
	nextEndTime, err := strconv.Atoi(resp.Payload.MarketHour.NextEndTime)
	if err != nil {
		return nil, err
	}
	period, err := strconv.Atoi(resp.Payload.MarketHour.Period)
	if err != nil {
		return nil, err
	}
	mhRoundInterval, err := strconv.Atoi(resp.Payload.MarketHour.RoundInterval)
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
		Version:                    resp.Payload.Version,
		MarketHourStartTime:        int64(nextStartTime),
		MarketHourEndTime:          int64(nextEndTime),
		MarketHourPeriod:           int64(period),
		MarketHourRoundInterval:    int64(mhRoundInterval),
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
	ctx context.Context, inputs []client.Input,
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
	resp, err := a.svc.ArkServiceRegisterInputsForNextRound(
		ark_service.NewArkServiceRegisterInputsForNextRoundParams().WithBody(body),
	)
	if err != nil {
		return "", err
	}

	return resp.Payload.RequestID, nil
}

func (a *restClient) RegisterNotesForNextRound(
	ctx context.Context, notes []string,
) (string, error) {
	body := &models.V1RegisterInputsForNextRoundRequest{
		Notes: notes,
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
	ctx context.Context, requestID string, outputs []client.Output, musig2 *tree.Musig2,
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
	if musig2 != nil {
		body.Musig2 = &models.V1Musig2{
			CosignersPublicKeys: musig2.CosignersPublicKeys,
			SigningAll:          musig2.SigningType == tree.SignAll,
		}
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
	ctx, cancel := context.WithCancel(ctx)
	eventsCh := make(chan client.RoundEventChannel)
	chunkCh := make(chan chunk)
	url := fmt.Sprintf("%s/v1/events", c.serverURL)

	go listenToStream(url, chunkCh)

	go func(ctx context.Context, eventsCh chan client.RoundEventChannel, chunkCh chan chunk) {
		defer close(eventsCh)

		for {
			select {
			case <-ctx.Done():
				return
			case chunk := <-chunkCh:
				if chunk.err == nil && len(chunk.msg) == 0 {
					continue
				}

				if chunk.err != nil {
					eventsCh <- client.RoundEventChannel{Err: chunk.err}
					return
				}
				// TODO: handle receival of partial chunks
				resp := ark_service.ArkServiceGetEventStreamOKBody{}
				if err := json.Unmarshal(chunk.msg, &resp); err != nil {
					eventsCh <- client.RoundEventChannel{
						Err: fmt.Errorf("failed to parse message from round event stream: %s, %s", err, string(chunk.msg)),
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
					return
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
					vtxoTree := treeFromProto{e.VtxoTree}.parse()
					connectorTree := treeFromProto{e.Connectors}.parse()

					minRelayFeeRate, err := strconv.Atoi(e.MinRelayFeeRate)
					if err != nil {
						_err = err
						break
					}

					event = client.RoundFinalizationEvent{
						ID:              e.ID,
						Tx:              e.RoundTx,
						Tree:            vtxoTree,
						Connectors:      connectorTree,
						MinRelayFeeRate: chainfee.SatPerKVByte(minRelayFeeRate),
						ConnectorsIndex: connectorsIndexFromProto{e.ConnectorsIndex}.parse(),
					}
				case resp.Result.RoundFinalized != nil:
					e := resp.Result.RoundFinalized
					event = client.RoundFinalizedEvent{
						ID:   e.ID,
						Txid: e.RoundTxid,
					}
				case resp.Result.RoundSigning != nil:
					e := resp.Result.RoundSigning
					event = client.RoundSigningStartedEvent{
						ID:               e.ID,
						UnsignedTree:     treeFromProto{e.UnsignedVtxoTree}.parse(),
						UnsignedRoundTx:  e.UnsignedRoundTx,
						CosignersPubkeys: e.CosignersPubkeys,
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
		}
	}(ctx, eventsCh, chunkCh)

	return eventsCh, cancel, nil
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
) (string, string, error) {
	req := &models.V1SubmitRedeemTxRequest{
		RedeemTx: redeemTx,
	}
	resp, err := a.svc.ArkServiceSubmitRedeemTx(
		ark_service.NewArkServiceSubmitRedeemTxParams().WithBody(req),
	)
	if err != nil {
		return "", "", err
	}
	return resp.Payload.SignedRedeemTx, resp.Payload.Txid, nil
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
		Connectors: treeFromProto{resp.Payload.Round.Connectors}.parse(),
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
		Connectors: treeFromProto{resp.Payload.Round.Connectors}.parse(),
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

func (c *restClient) GetTransactionsStream(ctx context.Context) (<-chan client.TransactionEvent, func(), error) {
	ctx, cancel := context.WithCancel(ctx)
	eventsCh := make(chan client.TransactionEvent)
	chunkCh := make(chan chunk)
	url := fmt.Sprintf("%s/v1/transactions", c.serverURL)

	go listenToStream(url, chunkCh)

	go func(ctx context.Context, eventsCh chan client.TransactionEvent, chunkCh chan chunk) {
		defer close(eventsCh)

		for {
			select {
			case <-ctx.Done():
				return
			case chunk := <-chunkCh:
				if chunk.err == nil && len(chunk.msg) == 0 {
					continue
				}

				if chunk.err != nil {
					eventsCh <- client.TransactionEvent{Err: chunk.err}
					return
				}

				resp := ark_service.ArkServiceGetTransactionsStreamOKBody{}
				if err := json.Unmarshal(chunk.msg, &resp); err != nil {
					eventsCh <- client.TransactionEvent{
						Err: fmt.Errorf("failed to parse message from transaction stream: %s", err),
					}
					return
				}

				emptyResp := ark_service.ArkServiceGetTransactionsStreamOKBody{}
				if resp == emptyResp {
					continue
				}

				if resp.Error != nil {
					eventsCh <- client.TransactionEvent{
						Err: fmt.Errorf("received error from transaction stream: %s", resp.Error.Message),
					}
					return
				}

				var event client.TransactionEvent
				if resp.Result.Round != nil {
					event = client.TransactionEvent{
						Round: &client.RoundTransaction{
							Txid:                 resp.Result.Round.Txid,
							SpentVtxos:           vtxosFromRest(resp.Result.Round.SpentVtxos),
							SpendableVtxos:       vtxosFromRest(resp.Result.Round.SpendableVtxos),
							ClaimedBoardingUtxos: outpointsFromRest(resp.Result.Round.ClaimedBoardingUtxos),
						},
					}
				} else if resp.Result.Redeem != nil {
					event = client.TransactionEvent{
						Redeem: &client.RedeemTransaction{
							Txid:           resp.Result.Redeem.Txid,
							SpentVtxos:     vtxosFromRest(resp.Result.Redeem.SpentVtxos),
							SpendableVtxos: vtxosFromRest(resp.Result.Redeem.SpendableVtxos),
						},
					}
				}

				eventsCh <- event
			}
		}
	}(ctx, eventsCh, chunkCh)

	return eventsCh, cancel, nil
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

func (c *restClient) SubscribeForAddress(ctx context.Context, addr string) (<-chan client.AddressEvent, func(), error) {
	ctx, cancel := context.WithCancel(ctx)
	eventsCh := make(chan client.AddressEvent)
	chunkCh := make(chan chunk)
	url := fmt.Sprintf("%s/v1/vtxos/%s/subscribe", c.serverURL, addr)

	go listenToStream(url, chunkCh)

	go func(eventsCh chan client.AddressEvent, chunkCh chan chunk) {
		defer close(eventsCh)

		for {
			select {
			case <-ctx.Done():
				return
			case chunk := <-chunkCh:
				if chunk.err == nil && len(chunk.msg) == 0 {
					continue
				}

				if chunk.err != nil {
					eventsCh <- client.AddressEvent{Err: chunk.err}
					return
				}

				resp := explorer_service.ExplorerServiceSubscribeForAddressOKBody{}
				if err := json.Unmarshal(chunk.msg, &resp); err != nil {
					eventsCh <- client.AddressEvent{
						Err: fmt.Errorf("failed to parse message from address stream: %s", err),
					}
					return
				}

				emptyResp := explorer_service.ExplorerServiceSubscribeForAddressOKBody{}
				if resp == emptyResp {
					continue
				}

				if resp.Error != nil {
					eventsCh <- client.AddressEvent{
						Err: fmt.Errorf("received error from address stream: %s", resp.Error.Message),
					}
					return
				}

				eventsCh <- client.AddressEvent{
					NewVtxos:   vtxosFromRest(resp.Result.NewVtxos),
					SpentVtxos: vtxosFromRest(resp.Result.SpentVtxos),
				}
			}
		}
	}(eventsCh, chunkCh)

	return eventsCh, cancel, nil
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

func newRestIndexerClient(
	serviceURL string,
) (indexer_service.ClientService, error) {
	parsedURL, err := url.Parse(serviceURL)
	if err != nil {
		return nil, err
	}

	schemes := []string{parsedURL.Scheme}
	host := parsedURL.Host
	basePath := parsedURL.Path

	if basePath == "" {
		basePath = indexerservice.DefaultBasePath
	}

	cfg := &indexerservice.TransportConfig{
		Host:     host,
		BasePath: basePath,
		Schemes:  schemes,
	}

	transport := httptransport.New(cfg.Host, cfg.BasePath, cfg.Schemes)
	svc := indexerservice.New(transport, strfmt.Default)
	return svc.IndexerService, nil
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

// treeFromProto is a wrapper type for V1Tree
type treeFromProto struct {
	*models.V1Tree
}

func (t treeFromProto) parse() tree.TxTree {
	if t.V1Tree == nil || t.Levels == nil {
		return tree.TxTree{}
	}

	vtxoTree := make(tree.TxTree, 0, len(t.Levels))
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

// connectorsIndexFromProto is a wrapper type for map[string]models.V1Outpoint
type connectorsIndexFromProto struct {
	connectorsIndex map[string]models.V1Outpoint
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

type chunk struct {
	msg []byte
	err error
}

func listenToStream(url string, chunkCh chan chunk) {
	defer close(chunkCh)

	httpClient := &http.Client{Timeout: time.Second * 0}

	resp, err := httpClient.Get(url)
	if err != nil {
		chunkCh <- chunk{err: err}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		chunkCh <- chunk{err: fmt.Errorf(
			"got unexpected status %d code", resp.StatusCode,
		)}
		return
	}

	reader := bufio.NewReader(resp.Body)
	for {
		msg, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				err = client.ErrConnectionClosedByServer
			}
			chunkCh <- chunk{err: err}
			return
		}
		msg = bytes.Trim(msg, "\n")
		chunkCh <- chunk{msg: msg}
	}
}

// IndexerService methods

func (a *restClient) GetCommitmentTx(ctx context.Context, txid string) (*client.CommitmentTxInfo, error) {
	params := indexer_service.NewIndexerServiceGetCommitmentTxParams().WithTxid(txid)
	resp, err := a.indexerSvc.IndexerServiceGetCommitmentTx(params)
	if err != nil {
		return nil, err
	}

	batches := make(map[uint32]*client.Batch)
	for vout, batch := range resp.Payload.Batches {
		voutUint32, err := strconv.ParseUint(vout, 10, 32)
		if err != nil {
			return nil, err
		}

		totalBatchAmount, err := strconv.ParseUint(batch.TotalBatchAmount, 10, 64)
		if err != nil {
			return nil, err
		}

		totalForfeitAmount, err := strconv.ParseUint(batch.TotalForfeitAmount, 10, 64)
		if err != nil {
			return nil, err
		}

		totalInputVtxos := int(batch.TotalInputVtxos)
		totalOutputVtxos := int(batch.TotalOutputVtxos)

		expiresAt, err := strconv.ParseInt(batch.ExpiresAt, 10, 64)
		if err != nil {
			return nil, err
		}

		batches[uint32(voutUint32)] = &client.Batch{
			TotalBatchAmount:   totalBatchAmount,
			TotalForfeitAmount: totalForfeitAmount,
			TotalInputVtxos:    int32(totalInputVtxos),
			TotalOutputVtxos:   int32(totalOutputVtxos),
			ExpiresAt:          expiresAt,
			Swept:              batch.Swept,
		}
	}

	startedAt, err := strconv.ParseInt(resp.Payload.StartedAt, 10, 64)
	if err != nil {
		return nil, err
	}

	endedAt, err := strconv.ParseInt(resp.Payload.EndedAt, 10, 64)
	if err != nil {
		return nil, err
	}

	return &client.CommitmentTxInfo{
		StartedAt: startedAt,
		EndedAt:   endedAt,
		Batches:   batches,
	}, nil
}

func (a *restClient) GetVtxoTree(ctx context.Context, batchOutpoint client.Outpoint, page client.PageRequest) (*client.VtxoTreeResponse, error) {
	pageSize := page.Size
	pageIndex := page.Index

	params := indexer_service.NewIndexerServiceGetVtxoTreeParams().
		WithBatchOutpointTxid(batchOutpoint.Txid).
		WithBatchOutpointVout(int64(batchOutpoint.VOut)).
		WithPageSize(&pageSize).
		WithPageIndex(&pageIndex)

	resp, err := a.indexerSvc.IndexerServiceGetVtxoTree(params)
	if err != nil {
		return nil, err
	}

	nodes := make([]client.IndexerNode, 0, len(resp.Payload.VtxoTree))
	for _, node := range resp.Payload.VtxoTree {
		nodes = append(nodes, client.IndexerNode{
			Txid:       node.Txid,
			ParentTxid: node.ParentTxid,
			Level:      node.Level,
			LevelIndex: node.LevelIndex,
		})
	}

	return &client.VtxoTreeResponse{
		VtxoTree: nodes,
		Page: client.PageResponse{
			Current: resp.Payload.Page.Current,
			Next:    resp.Payload.Page.Next,
			Total:   resp.Payload.Page.Total,
		},
	}, nil
}

func (a *restClient) GetForfeitTxs(ctx context.Context, batchOutpoint client.Outpoint, page client.PageRequest) (*client.ForfeitTxsResponse, error) {
	pageSize := page.Size
	pageIndex := page.Index

	params := indexer_service.NewIndexerServiceGetForfeitTxsParams().
		WithBatchOutpointTxid(batchOutpoint.Txid).
		WithBatchOutpointVout(int64(batchOutpoint.VOut)).
		WithPageSize(&pageSize).
		WithPageIndex(&pageIndex)

	resp, err := a.indexerSvc.IndexerServiceGetForfeitTxs(params)
	if err != nil {
		return nil, err
	}

	return &client.ForfeitTxsResponse{
		Txs: resp.Payload.Txs,
		Page: client.PageResponse{
			Current: resp.Payload.Page.Current,
			Next:    resp.Payload.Page.Next,
			Total:   resp.Payload.Page.Total,
		},
	}, nil
}

func (a *restClient) GetConnectors(ctx context.Context, batchOutpoint client.Outpoint, page client.PageRequest) (*client.ConnectorsResponse, error) {
	pageSize := page.Size
	pageIndex := page.Index

	params := indexer_service.NewIndexerServiceGetConnectorsParams().
		WithBatchOutpointTxid(batchOutpoint.Txid).
		WithBatchOutpointVout(int64(batchOutpoint.VOut)).
		WithPageSize(&pageSize).
		WithPageIndex(&pageIndex)

	resp, err := a.indexerSvc.IndexerServiceGetConnectors(params)
	if err != nil {
		return nil, err
	}

	connectors := make([]client.IndexerNode, 0, len(resp.Payload.Connectors))
	for _, connector := range resp.Payload.Connectors {
		connectors = append(connectors, client.IndexerNode{
			Txid:       connector.Txid,
			ParentTxid: connector.ParentTxid,
			Level:      connector.Level,
			LevelIndex: connector.LevelIndex,
		})
	}

	return &client.ConnectorsResponse{
		Connectors: connectors,
		Page: client.PageResponse{
			Current: resp.Payload.Page.Current,
			Next:    resp.Payload.Page.Next,
			Total:   resp.Payload.Page.Total,
		},
	}, nil
}

func (a *restClient) GetSpendableVtxos(ctx context.Context, address string, page client.PageRequest) (*client.SpendableVtxosResponse, error) {
	pageSize := page.Size
	pageIndex := page.Index

	params := indexer_service.NewIndexerServiceGetSpendableVtxosParams().
		WithAddress(address).
		WithPageSize(&pageSize).
		WithPageIndex(&pageIndex)

	resp, err := a.indexerSvc.IndexerServiceGetSpendableVtxos(params)
	if err != nil {
		return nil, err
	}

	vtxos := make([]client.IndexerVtxo, 0, len(resp.Payload.Vtxos))
	for _, vtxo := range resp.Payload.Vtxos {
		createdAt, err := strconv.ParseInt(vtxo.CreatedAt, 10, 64)
		if err != nil {
			return nil, err
		}

		expiresAt, err := strconv.ParseInt(vtxo.ExpiresAt, 10, 64)
		if err != nil {
			return nil, err
		}

		amount, err := strconv.ParseUint(vtxo.Amount, 10, 64)
		if err != nil {
			return nil, err
		}

		vtxos = append(vtxos, client.IndexerVtxo{
			Outpoint: client.Outpoint{
				Txid: vtxo.Outpoint.Txid,
				VOut: uint32(vtxo.Outpoint.Vout),
			},
			CreatedAt: createdAt,
			ExpiresAt: expiresAt,
			Amount:    amount,
			Script:    vtxo.Script,
			IsLeaf:    vtxo.IsLeaf,
			IsSwept:   vtxo.IsSwept,
			IsSpent:   vtxo.IsSpent,
			SpentBy:   vtxo.SpentBy,
		})
	}

	return &client.SpendableVtxosResponse{
		Vtxos: vtxos,
		Page: client.PageResponse{
			Current: resp.Payload.Page.Current,
			Next:    resp.Payload.Page.Next,
			Total:   resp.Payload.Page.Total,
		},
	}, nil
}

func (a *restClient) GetTransactionHistory(ctx context.Context, address string, startTime, endTime int64, page client.PageRequest) (*client.TransactionHistoryResponse, error) {
	startTimeStr := strconv.FormatInt(startTime, 10)
	endTimeStr := strconv.FormatInt(endTime, 10)
	pageSize := page.Size
	pageIndex := page.Index

	params := indexer_service.NewIndexerServiceGetTransactionHistoryParams().
		WithAddress(address).
		WithStartTime(&startTimeStr).
		WithEndTime(&endTimeStr).
		WithPageSize(&pageSize).
		WithPageIndex(&pageIndex)

	resp, err := a.indexerSvc.IndexerServiceGetTransactionHistory(params)
	if err != nil {
		return nil, err
	}

	history := make([]client.TxHistoryRecord, 0, len(resp.Payload.History))
	for _, record := range resp.Payload.History {
		amount, err := strconv.ParseUint(record.Amount, 10, 64)
		if err != nil {
			return nil, err
		}

		createdAt, err := strconv.ParseInt(record.CreatedAt, 10, 64)
		if err != nil {
			return nil, err
		}

		confirmedAt, err := strconv.ParseInt(record.ConfirmedAt, 10, 64)
		if err != nil {
			return nil, err
		}

		var txid string
		switch {
		case record.BoardingTxid != "":
			txid = record.BoardingTxid
		case record.CommitmentTxid != "":
			txid = record.CommitmentTxid
		case record.SweepTxid != "":
			txid = record.SweepTxid
		case record.ArkTxid != "":
			txid = record.ArkTxid
		}

		// Use a zero value for TxType if Type is nil, otherwise use a numeric conversion
		var txType client.TxType
		if record.Type != nil {
			// Convert the string enum to a numeric value
			typeStr := string(*record.Type)
			switch typeStr {
			case "INDEXER_TX_TYPE_RECEIVED":
				txType = client.TxTypeReceived
			case "INDEXER_TX_TYPE_SENT":
				txType = client.TxTypeSent
			case "INDEXER_TX_TYPE_SWEEP":
				txType = client.TxTypeSweep
			default:
				// Default to unspecified for unknown types
				txType = client.TxTypeUnspecified
			}
		}

		history = append(history, client.TxHistoryRecord{
			Txid:        txid,
			Type:        txType,
			Amount:      amount,
			CreatedAt:   createdAt,
			ConfirmedAt: confirmedAt,
			IsSettled:   record.IsSettled,
		})
	}

	return &client.TransactionHistoryResponse{
		History: history,
		Page: client.PageResponse{
			Current: resp.Payload.Page.Current,
			Next:    resp.Payload.Page.Next,
			Total:   resp.Payload.Page.Total,
		},
	}, nil
}

func (a *restClient) GetVtxoChain(ctx context.Context, outpoint client.Outpoint, page client.PageRequest) (*client.VtxoChainResponse, error) {
	pageSize := page.Size
	pageIndex := page.Index

	params := indexer_service.NewIndexerServiceGetVtxoChainParams().
		WithOutpointTxid(outpoint.Txid).
		WithOutpointVout(int64(outpoint.VOut)).
		WithPageSize(&pageSize).
		WithPageIndex(&pageIndex)

	resp, err := a.indexerSvc.IndexerServiceGetVtxoChain(params)
	if err != nil {
		return nil, err
	}

	graph := make(map[string]*client.ChainWithExpiry)
	for k, v := range resp.Payload.Graph {
		txs := make([]client.ChainTx, 0, len(v.Txs))
		for _, tx := range v.Txs {
			txType := "virtual"
			if *tx.Type == models.V1IndexerChainedTxTypeINDEXERCHAINEDTXTYPECOMMITMENT {
				txType = "commitment"
			}
			txs = append(txs, client.ChainTx{
				Txid: tx.Txid,
				Type: txType,
			})
		}
		expiresAt, err := strconv.ParseInt(v.ExpiresAt, 10, 64)
		if err != nil {
			return nil, err
		}
		graph[k] = &client.ChainWithExpiry{
			Txs:       txs,
			ExpiresAt: expiresAt,
		}
	}

	return &client.VtxoChainResponse{
		Graph: graph,
		Page: client.PageResponse{
			Current: resp.Payload.Page.Current,
			Next:    resp.Payload.Page.Next,
			Total:   resp.Payload.Page.Total,
		},
	}, nil
}

func (a *restClient) GetVirtualTxs(ctx context.Context, txids []string, page client.PageRequest) (*client.VirtualTxsResponse, error) {
	pageSize := page.Size
	pageIndex := page.Index

	params := indexer_service.NewIndexerServiceGetVirtualTxsParams().
		WithTxids(txids).
		WithPageSize(&pageSize).
		WithPageIndex(&pageIndex)

	resp, err := a.indexerSvc.IndexerServiceGetVirtualTxs(params)
	if err != nil {
		return nil, err
	}

	return &client.VirtualTxsResponse{
		Txs: resp.Payload.Txs,
		Page: client.PageResponse{
			Current: resp.Payload.Page.Current,
			Next:    resp.Payload.Page.Next,
			Total:   resp.Payload.Page.Total,
		},
	}, nil
}

func (a *restClient) GetSweptCommitmentTx(ctx context.Context, txid string) (*client.SweptCommitmentTxResponse, error) {
	params := indexer_service.NewIndexerServiceGetSweptCommitmentTxParams().WithTxid(txid)

	resp, err := a.indexerSvc.IndexerServiceGetSweptCommitmentTx(params)
	if err != nil {
		return nil, err
	}

	return &client.SweptCommitmentTxResponse{
		SweptBy: resp.Payload.SweptBy,
	}, nil
}
