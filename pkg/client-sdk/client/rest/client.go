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

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/client/rest/service/arkservice"
	"github.com/ark-network/ark/pkg/client-sdk/client/rest/service/arkservice/ark_service"
	"github.com/ark-network/ark/pkg/client-sdk/client/rest/service/models"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// restClient implements the TransportClient interface for REST communication
type restClient struct {
	serverURL      string
	svc            ark_service.ClientService
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

	// TODO: use twice the round interval.
	reqTimeout := 15 * time.Second
	treeCache := utils.NewCache[tree.TxTree]()

	return &restClient{serverURL, svc, reqTimeout, treeCache}, nil
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
	boardingExitDelay, err := strconv.Atoi(resp.Payload.BoardingExitDelay)
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
	utxoMinAmount, err := strconv.Atoi(resp.Payload.UtxoMinAmount)
	if err != nil {
		return nil, err
	}
	utxoMaxAmount, err := strconv.Atoi(resp.Payload.UtxoMaxAmount)
	if err != nil {
		return nil, err
	}
	vtxoMinAmount, err := strconv.Atoi(resp.Payload.VtxoMinAmount)
	if err != nil {
		return nil, err
	}
	vtxoMaxAmount, err := strconv.Atoi(resp.Payload.VtxoMaxAmount)
	if err != nil {
		return nil, err
	}

	return &client.Info{
		PubKey:                  resp.Payload.Pubkey,
		VtxoTreeExpiry:          int64(vtxoTreeExpiry),
		UnilateralExitDelay:     int64(unilateralExitDelay),
		RoundInterval:           int64(roundInterval),
		Network:                 resp.Payload.Network,
		Dust:                    uint64(dust),
		BoardingExitDelay:       int64(boardingExitDelay),
		ForfeitAddress:          resp.Payload.ForfeitAddress,
		Version:                 resp.Payload.Version,
		MarketHourStartTime:     int64(nextStartTime),
		MarketHourEndTime:       int64(nextEndTime),
		MarketHourPeriod:        int64(period),
		MarketHourRoundInterval: int64(mhRoundInterval),
		UtxoMinAmount:           int64(utxoMinAmount),
		UtxoMaxAmount:           int64(utxoMaxAmount),
		VtxoMinAmount:           int64(vtxoMinAmount),
		VtxoMaxAmount:           int64(vtxoMaxAmount),
	}, nil
}

func (a *restClient) RegisterIntent(
	ctx context.Context,
	signature, message string,
) (string, error) {
	body := &models.V1RegisterIntentRequest{
		Intent: &models.V1Bip322Signature{
			Message:   message,
			Signature: signature,
		},
	}
	resp, err := a.svc.ArkServiceRegisterIntent(
		ark_service.NewArkServiceRegisterIntentParams().WithBody(body),
	)
	if err != nil {
		return "", err
	}

	return resp.Payload.IntentID, nil
}

func (a *restClient) DeleteIntent(_ context.Context, signature, message string) error {
	body := &models.V1DeleteIntentRequest{
		Proof: &models.V1Bip322Signature{
			Message:   message,
			Signature: signature,
		},
	}

	_, err := a.svc.ArkServiceDeleteIntent(
		ark_service.NewArkServiceDeleteIntentParams().WithBody(body),
	)
	return err
}

func (a *restClient) ConfirmRegistration(ctx context.Context, intentID string) error {
	body := &models.V1ConfirmRegistrationRequest{
		IntentID: intentID,
	}
	_, err := a.svc.ArkServiceConfirmRegistration(
		ark_service.NewArkServiceConfirmRegistrationParams().WithBody(body),
	)
	return err
}

func (a *restClient) SubmitTreeNonces(ctx context.Context, batchId, cosignerPubkey string, nonces tree.TreeNonces) error {
	var nonceBuffer bytes.Buffer
	if err := nonces.Encode(&nonceBuffer); err != nil {
		return err
	}
	serializedNonces := hex.EncodeToString(nonceBuffer.Bytes())

	body := &models.V1SubmitTreeNoncesRequest{
		BatchID:    batchId,
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
	ctx context.Context, batchId, cosignerPubkey string, signatures tree.TreePartialSigs,
) error {
	var sigsBuffer bytes.Buffer
	if err := signatures.Encode(&sigsBuffer); err != nil {
		return err
	}
	serializedSigs := hex.EncodeToString(sigsBuffer.Bytes())

	body := &models.V1SubmitTreeSignaturesRequest{
		BatchID:        batchId,
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
	ctx context.Context, signedForfeitTxs []string, signedCommitmentTx string,
) error {
	body := models.V1SubmitSignedForfeitTxsRequest{
		SignedForfeitTxs:   signedForfeitTxs,
		SignedCommitmentTx: signedCommitmentTx,
	}
	_, err := a.svc.ArkServiceSubmitSignedForfeitTxs(
		ark_service.NewArkServiceSubmitSignedForfeitTxsParams().WithBody(&body),
	)
	return err
}

func (c *restClient) GetEventStream(ctx context.Context) (<-chan client.RoundEventChannel, func(), error) {
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
				case resp.Result.BatchFailed != nil:
					e := resp.Result.BatchFailed
					event = client.RoundFailedEvent{
						ID:     e.ID,
						Reason: e.Reason,
					}
				case resp.Result.BatchStarted != nil:
					e := resp.Result.BatchStarted
					batchExpiry, err := strconv.ParseUint(e.BatchExpiry, 10, 32)
					if err != nil {
						_err = err
						break
					}
					event = client.BatchStartedEvent{
						ID:             e.ID,
						IntentIdHashes: e.IntentIDHashes,
						BatchExpiry:    int64(batchExpiry),
						ForfeitAddress: e.ForfeitAddress,
					}
				case resp.Result.BatchFinalization != nil:
					e := resp.Result.BatchFinalization

					event = client.RoundFinalizationEvent{
						ID:              e.ID,
						Tx:              e.CommitmentTx,
						ConnectorsIndex: connectorsIndexFromProto{e.ConnectorsIndex}.parse(),
					}
				case resp.Result.BatchFinalized != nil:
					e := resp.Result.BatchFinalized
					event = client.RoundFinalizedEvent{
						ID:   e.ID,
						Txid: e.CommitmentTxid,
					}
				case resp.Result.TreeSigningStarted != nil:
					e := resp.Result.TreeSigningStarted
					event = client.RoundSigningStartedEvent{
						ID:               e.ID,
						UnsignedRoundTx:  e.UnsignedCommitmentTx,
						CosignersPubkeys: e.CosignersPubkeys,
					}
				case resp.Result.TreeNoncesAggregated != nil:
					e := resp.Result.TreeNoncesAggregated
					reader := hex.NewDecoder(strings.NewReader(e.TreeNonces))
					nonces, err := tree.DecodeNonces(reader)
					if err != nil {
						_err = err
						break
					}
					event = client.RoundSigningNoncesGeneratedEvent{
						ID:     e.ID,
						Nonces: nonces,
					}
				case resp.Result.TreeTx != nil:
					e := resp.Result.TreeTx
					event = client.BatchTreeEvent{
						ID:    e.ID,
						Topic: e.Topic,
						Node: tree.Node{
							Txid:       e.TreeTx.Txid,
							Tx:         e.TreeTx.Tx,
							ParentTxid: e.TreeTx.ParentTxid,
							Leaf:       e.TreeTx.Leaf,
							Level:      e.TreeTx.Level,
							LevelIndex: e.TreeTx.LevelIndex,
						},
					}
				case resp.Result.TreeSignature != nil:
					e := resp.Result.TreeSignature
					event = client.BatchTreeSignatureEvent{
						ID:         e.ID,
						Topic:      e.Topic,
						Level:      e.Level,
						LevelIndex: e.LevelIndex,
						Signature:  e.Signature,
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

func (a *restClient) SubmitTx(
	ctx context.Context, signedVirtualTx string, checkpointTxs []string,
) (string, string, []string, error) {
	req := &models.V1SubmitTxRequest{
		SignedVirtualTx: signedVirtualTx,
		CheckpointTxs:   checkpointTxs,
	}
	resp, err := a.svc.ArkServiceSubmitTx(
		ark_service.NewArkServiceSubmitTxParams().WithBody(req),
	)
	if err != nil {
		return "", "", nil, err
	}
	return resp.Payload.Txid, resp.Payload.FinalVirtualTx, resp.Payload.SignedCheckpointTxs, nil
}

func (a *restClient) FinalizeTx(
	ctx context.Context, virtualTxid string, finalCheckpointsTxs []string,
) error {
	req := &models.V1FinalizeTxRequest{
		Txid:               virtualTxid,
		FinalCheckpointTxs: finalCheckpointsTxs,
	}
	_, err := a.svc.ArkServiceFinalizeTx(
		ark_service.NewArkServiceFinalizeTxParams().WithBody(req),
	)
	return err
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
				if resp.Result.CommitmentTx != nil {
					event = client.TransactionEvent{
						Round: &client.RoundTransaction{
							Txid:           resp.Result.CommitmentTx.Txid,
							SpentVtxos:     vtxosFromRest(resp.Result.CommitmentTx.SpentVtxos),
							SpendableVtxos: vtxosFromRest(resp.Result.CommitmentTx.SpendableVtxos),
							Hex:            resp.Result.CommitmentTx.Hex,
						},
					}
				} else if resp.Result.VirtualTx != nil {
					event = client.TransactionEvent{
						Redeem: &client.RedeemTransaction{
							Txid:           resp.Result.VirtualTx.Txid,
							SpentVtxos:     vtxosFromRest(resp.Result.VirtualTx.SpentVtxos),
							SpendableVtxos: vtxosFromRest(resp.Result.VirtualTx.SpendableVtxos),
							Hex:            resp.Result.VirtualTx.Hex,
						},
					}
				}

				eventsCh <- event
			}
		}
	}(ctx, eventsCh, chunkCh)

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

func vtxosFromRest(restVtxos []*models.V1Vtxo) []client.Vtxo {
	vtxos := make([]client.Vtxo, len(restVtxos))
	for i, v := range restVtxos {
		var expiresAt, createdAt time.Time
		if v.ExpiresAt != "" && v.ExpiresAt != "0" {
			expAt, err := strconv.Atoi(v.ExpiresAt)
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
			RoundTxid: v.CommitmentTxid,
			ExpiresAt: expiresAt,
			IsPending: v.Preconfirmed,
			SpentBy:   v.SpentBy,
			CreatedAt: createdAt,
			Swept:     v.Swept,
			Spent:     v.Spent,
		}
	}
	return vtxos
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
	// nolint:all
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
