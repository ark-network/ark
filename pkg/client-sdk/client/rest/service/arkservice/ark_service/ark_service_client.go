// Code generated by go-swagger; DO NOT EDIT.

package ark_service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new ark service API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new ark service API client with basic auth credentials.
// It takes the following parameters:
// - host: http host (github.com).
// - basePath: any base path for the API client ("/v1", "/v3").
// - scheme: http scheme ("http", "https").
// - user: user for basic authentication header.
// - password: password for basic authentication header.
func NewClientWithBasicAuth(host, basePath, scheme, user, password string) ClientService {
	transport := httptransport.New(host, basePath, []string{scheme})
	transport.DefaultAuthentication = httptransport.BasicAuth(user, password)
	return &Client{transport: transport, formats: strfmt.Default}
}

// New creates a new ark service API client with a bearer token for authentication.
// It takes the following parameters:
// - host: http host (github.com).
// - basePath: any base path for the API client ("/v1", "/v3").
// - scheme: http scheme ("http", "https").
// - bearerToken: bearer token for Bearer authentication header.
func NewClientWithBearerToken(host, basePath, scheme, bearerToken string) ClientService {
	transport := httptransport.New(host, basePath, []string{scheme})
	transport.DefaultAuthentication = httptransport.BearerToken(bearerToken)
	return &Client{transport: transport, formats: strfmt.Default}
}

/*
Client for ark service API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	ArkServiceClaimPayment(params *ArkServiceClaimPaymentParams, opts ...ClientOption) (*ArkServiceClaimPaymentOK, error)

	ArkServiceFinalizePayment(params *ArkServiceFinalizePaymentParams, opts ...ClientOption) (*ArkServiceFinalizePaymentOK, error)

	ArkServiceGetEventStream(params *ArkServiceGetEventStreamParams, opts ...ClientOption) (*ArkServiceGetEventStreamOK, error)

	ArkServiceGetInfo(params *ArkServiceGetInfoParams, opts ...ClientOption) (*ArkServiceGetInfoOK, error)

	ArkServiceGetRound(params *ArkServiceGetRoundParams, opts ...ClientOption) (*ArkServiceGetRoundOK, error)

	ArkServiceGetRoundByID(params *ArkServiceGetRoundByIDParams, opts ...ClientOption) (*ArkServiceGetRoundByIDOK, error)

	ArkServiceListVtxos(params *ArkServiceListVtxosParams, opts ...ClientOption) (*ArkServiceListVtxosOK, error)

	ArkServiceOnboard(params *ArkServiceOnboardParams, opts ...ClientOption) (*ArkServiceOnboardOK, error)

	ArkServicePing(params *ArkServicePingParams, opts ...ClientOption) (*ArkServicePingOK, error)

	ArkServiceRegisterPayment(params *ArkServiceRegisterPaymentParams, opts ...ClientOption) (*ArkServiceRegisterPaymentOK, error)

	ArkServiceTrustedOnboarding(params *ArkServiceTrustedOnboardingParams, opts ...ClientOption) (*ArkServiceTrustedOnboardingOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
ArkServiceClaimPayment ark service claim payment API
*/
func (a *Client) ArkServiceClaimPayment(params *ArkServiceClaimPaymentParams, opts ...ClientOption) (*ArkServiceClaimPaymentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceClaimPaymentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_ClaimPayment",
		Method:             "POST",
		PathPattern:        "/v1/payment/claim",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceClaimPaymentReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ArkServiceClaimPaymentOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceClaimPaymentDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
ArkServiceFinalizePayment ark service finalize payment API
*/
func (a *Client) ArkServiceFinalizePayment(params *ArkServiceFinalizePaymentParams, opts ...ClientOption) (*ArkServiceFinalizePaymentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceFinalizePaymentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_FinalizePayment",
		Method:             "POST",
		PathPattern:        "/v1/payment/finalize",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceFinalizePaymentReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ArkServiceFinalizePaymentOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceFinalizePaymentDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
ArkServiceGetEventStream ark service get event stream API
*/
func (a *Client) ArkServiceGetEventStream(params *ArkServiceGetEventStreamParams, opts ...ClientOption) (*ArkServiceGetEventStreamOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceGetEventStreamParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_GetEventStream",
		Method:             "GET",
		PathPattern:        "/v1/events",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceGetEventStreamReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ArkServiceGetEventStreamOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceGetEventStreamDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
ArkServiceGetInfo ark service get info API
*/
func (a *Client) ArkServiceGetInfo(params *ArkServiceGetInfoParams, opts ...ClientOption) (*ArkServiceGetInfoOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceGetInfoParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_GetInfo",
		Method:             "GET",
		PathPattern:        "/v1/info",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceGetInfoReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ArkServiceGetInfoOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceGetInfoDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
ArkServiceGetRound ts o d o b t c sign tree rpc
*/
func (a *Client) ArkServiceGetRound(params *ArkServiceGetRoundParams, opts ...ClientOption) (*ArkServiceGetRoundOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceGetRoundParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_GetRound",
		Method:             "GET",
		PathPattern:        "/v1/round/{txid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceGetRoundReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ArkServiceGetRoundOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceGetRoundDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
ArkServiceGetRoundByID ark service get round by Id API
*/
func (a *Client) ArkServiceGetRoundByID(params *ArkServiceGetRoundByIDParams, opts ...ClientOption) (*ArkServiceGetRoundByIDOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceGetRoundByIDParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_GetRoundById",
		Method:             "GET",
		PathPattern:        "/v1/round/id/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceGetRoundByIDReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ArkServiceGetRoundByIDOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceGetRoundByIDDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
ArkServiceListVtxos ark service list vtxos API
*/
func (a *Client) ArkServiceListVtxos(params *ArkServiceListVtxosParams, opts ...ClientOption) (*ArkServiceListVtxosOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceListVtxosParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_ListVtxos",
		Method:             "GET",
		PathPattern:        "/v1/vtxos/{address}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceListVtxosReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ArkServiceListVtxosOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceListVtxosDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
ArkServiceOnboard ark service onboard API
*/
func (a *Client) ArkServiceOnboard(params *ArkServiceOnboardParams, opts ...ClientOption) (*ArkServiceOnboardOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceOnboardParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_Onboard",
		Method:             "POST",
		PathPattern:        "/v1/onboard",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceOnboardReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ArkServiceOnboardOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceOnboardDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
ArkServicePing ark service ping API
*/
func (a *Client) ArkServicePing(params *ArkServicePingParams, opts ...ClientOption) (*ArkServicePingOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServicePingParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_Ping",
		Method:             "GET",
		PathPattern:        "/v1/ping/{paymentId}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServicePingReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ArkServicePingOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServicePingDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
ArkServiceRegisterPayment ark service register payment API
*/
func (a *Client) ArkServiceRegisterPayment(params *ArkServiceRegisterPaymentParams, opts ...ClientOption) (*ArkServiceRegisterPaymentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceRegisterPaymentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_RegisterPayment",
		Method:             "POST",
		PathPattern:        "/v1/payment/register",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceRegisterPaymentReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ArkServiceRegisterPaymentOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceRegisterPaymentDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
ArkServiceTrustedOnboarding ark service trusted onboarding API
*/
func (a *Client) ArkServiceTrustedOnboarding(params *ArkServiceTrustedOnboardingParams, opts ...ClientOption) (*ArkServiceTrustedOnboardingOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceTrustedOnboardingParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_TrustedOnboarding",
		Method:             "POST",
		PathPattern:        "/v1/onboard/address",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceTrustedOnboardingReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ArkServiceTrustedOnboardingOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceTrustedOnboardingDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
