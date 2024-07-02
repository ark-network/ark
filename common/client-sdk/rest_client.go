package arkclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
)

func NewRestClient(baseURL string, httpClient *http.Client) (ArkRestClient, error) {
	if baseURL == "" {
		return nil, errAspUrlEmpty
	}

	return &arkRestClient{baseURL: baseURL, httpClient: httpClient}, nil
}

type ArkRestClient interface {
	Admin() AdminServiceClient
	Service() ArkServiceClient
}

type AdminServiceClient interface {
	GetBalance(
		ctx context.Context, req *arkv1.GetBalanceRequest,
	) (*arkv1.GetBalanceResponse, error)
	GetScheduledSweep(
		ctx context.Context, req *arkv1.GetScheduledSweepRequest,
	) (*arkv1.GetScheduledSweepResponse, error)
	GetRoundDetails(
		ctx context.Context, req *arkv1.GetRoundDetailsRequest,
	) (*arkv1.GetRoundDetailsResponse, error)
	GetRounds(
		ctx context.Context, req *arkv1.GetRoundsRequest,
	) (*arkv1.GetRoundsResponse, error)
}

type ArkServiceClient interface {
	RegisterPayment(
		ctx context.Context, req *arkv1.RegisterPaymentRequest,
	) (*arkv1.RegisterPaymentResponse, error)
	ClaimPayment(
		ctx context.Context, req *arkv1.ClaimPaymentRequest,
	) (*arkv1.ClaimPaymentResponse, error)
	FinalizePayment(
		ctx context.Context, req *arkv1.FinalizePaymentRequest,
	) (*arkv1.FinalizePaymentResponse, error)
	GetRound(
		ctx context.Context, req *arkv1.GetRoundRequest,
	) (*arkv1.GetRoundResponse, error)
	GetEventStream(
		ctx context.Context, req *arkv1.GetEventStreamRequest,
	) (arkv1.ArkService_GetEventStreamClient, error)
	Ping(
		ctx context.Context, req *arkv1.PingRequest,
	) (*arkv1.PingResponse, error)
	ListVtxos(
		ctx context.Context, req *arkv1.ListVtxosRequest,
	) (*arkv1.ListVtxosResponse, error)
	GetInfo(
		ctx context.Context, req *arkv1.GetInfoRequest,
	) (*arkv1.GetInfoResponse, error)
	Onboard(
		ctx context.Context, req *arkv1.OnboardRequest,
	) (*arkv1.OnboardResponse, error)
	TrustedOnboarding(
		ctx context.Context, req *arkv1.TrustedOnboardingRequest,
	) (*arkv1.TrustedOnboardingResponse, error)
}

type arkRestClient struct {
	baseURL    string
	httpClient *http.Client
}

func (c *arkRestClient) Admin() AdminServiceClient {
	return &restAdminServiceClient{baseURL: c.baseURL, client: c.httpClient}
}

func (c *arkRestClient) Service() ArkServiceClient {
	return &restArkServiceClient{baseURL: c.baseURL, client: c.httpClient}
}

type restAdminServiceClient struct {
	baseURL string
	client  *http.Client
}

func (c *restAdminServiceClient) GetBalance(
	ctx context.Context, req *arkv1.GetBalanceRequest,
) (*arkv1.GetBalanceResponse, error) {
	resp, err := c.client.Get(c.baseURL + "/v1/admin/balance")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var restResp arkv1.GetBalanceResponse
	if err := json.NewDecoder(resp.Body).Decode(&restResp); err != nil {
		return nil, err
	}
	return &restResp, nil
}

func (c *restAdminServiceClient) GetScheduledSweep(
	ctx context.Context, req *arkv1.GetScheduledSweepRequest,
) (*arkv1.GetScheduledSweepResponse, error) {
	resp, err := c.client.Get(c.baseURL + "/v1/admin/sweeps")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var restResp arkv1.GetScheduledSweepResponse
	if err := json.NewDecoder(resp.Body).Decode(&restResp); err != nil {
		return nil, err
	}
	return &restResp, nil
}

func (c *restAdminServiceClient) GetRoundDetails(
	ctx context.Context, req *arkv1.GetRoundDetailsRequest,
) (*arkv1.GetRoundDetailsResponse, error) {
	resp, err := c.client.Get(c.baseURL + "/v1/admin/round/" + req.RoundId)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var restResp arkv1.GetRoundDetailsResponse
	if err := json.NewDecoder(resp.Body).Decode(&restResp); err != nil {
		return nil, err
	}
	return &restResp, nil
}

func (c *restAdminServiceClient) GetRounds(
	ctx context.Context, req *arkv1.GetRoundsRequest,
) (*arkv1.GetRoundsResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Post(
		c.baseURL+"/v1/admin/rounds",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var restResp arkv1.GetRoundsResponse
	if err := json.NewDecoder(resp.Body).Decode(&restResp); err != nil {
		return nil, err
	}
	return &restResp, nil
}

type restArkServiceClient struct {
	baseURL string
	client  *http.Client
}

func (c *restArkServiceClient) RegisterPayment(
	ctx context.Context, req *arkv1.RegisterPaymentRequest,
) (*arkv1.RegisterPaymentResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Post(
		c.baseURL+"/v1/payment/register",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var restResp arkv1.RegisterPaymentResponse
	if err := json.NewDecoder(resp.Body).Decode(&restResp); err != nil {
		return nil, err
	}
	return &restResp, nil
}

func (c *restArkServiceClient) ClaimPayment(
	ctx context.Context, req *arkv1.ClaimPaymentRequest,
) (*arkv1.ClaimPaymentResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Post(
		c.baseURL+"/v1/payment/claim",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var restResp arkv1.ClaimPaymentResponse
	if err := json.NewDecoder(resp.Body).Decode(&restResp); err != nil {
		return nil, err
	}
	return &restResp, nil
}

func (c *restArkServiceClient) FinalizePayment(
	ctx context.Context, req *arkv1.FinalizePaymentRequest,
) (*arkv1.FinalizePaymentResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Post(
		c.baseURL+"/v1/payment/finalize",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var restResp arkv1.FinalizePaymentResponse
	if err := json.NewDecoder(resp.Body).Decode(&restResp); err != nil {
		return nil, err
	}
	return &restResp, nil
}

func (c *restArkServiceClient) GetRound(
	ctx context.Context, req *arkv1.GetRoundRequest,
) (*arkv1.GetRoundResponse, error) {
	resp, err := c.client.Get(c.baseURL + "/v1/round/" + req.Txid)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var restResp arkv1.GetRoundResponse
	if err := json.NewDecoder(resp.Body).Decode(&restResp); err != nil {
		return nil, err
	}
	return &restResp, nil
}

func (c *restArkServiceClient) GetEventStream(
	ctx context.Context, req *arkv1.GetEventStreamRequest,
) (arkv1.ArkService_GetEventStreamClient, error) {
	return nil, errors.New("not implemented for REST client")
}

func (c *restArkServiceClient) Ping(
	ctx context.Context, req *arkv1.PingRequest,
) (*arkv1.PingResponse, error) {
	resp, err := c.client.Get(c.baseURL + "/v1/ping/" + req.PaymentId)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var restResp arkv1.PingResponse
	if err := json.NewDecoder(resp.Body).Decode(&restResp); err != nil {
		return nil, err
	}
	return &restResp, nil
}

func (c *restArkServiceClient) ListVtxos(
	ctx context.Context, req *arkv1.ListVtxosRequest,
) (*arkv1.ListVtxosResponse, error) {
	resp, err := c.client.Get(c.baseURL + "/v1/vtxos/" + req.Address)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var restResp arkv1.ListVtxosResponse
	if err := json.NewDecoder(resp.Body).Decode(&restResp); err != nil {
		return nil, err
	}
	return &restResp, nil
}

func (c *restArkServiceClient) GetInfo(
	ctx context.Context, req *arkv1.GetInfoRequest,
) (*arkv1.GetInfoResponse, error) {
	resp, err := c.client.Get(c.baseURL + "/v1/info")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var restResp arkv1.GetInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&restResp); err != nil {
		return nil, err
	}
	return &restResp, nil
}

func (c *restArkServiceClient) Onboard(
	ctx context.Context, req *arkv1.OnboardRequest,
) (*arkv1.OnboardResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Post(
		c.baseURL+"/v1/onboard",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var restResp arkv1.OnboardResponse
	if err := json.NewDecoder(resp.Body).Decode(&restResp); err != nil {
		return nil, err
	}
	return &restResp, nil
}

func (c *restArkServiceClient) TrustedOnboarding(
	ctx context.Context, req *arkv1.TrustedOnboardingRequest,
) (*arkv1.TrustedOnboardingResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Post(
		c.baseURL+"/v1/onboard/address",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var restResp arkv1.TrustedOnboardingResponse
	if err := json.NewDecoder(resp.Body).Decode(&restResp); err != nil {
		return nil, err
	}
	return &restResp, nil
}
