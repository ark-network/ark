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
	ArkServiceDeleteNostrRecipient(params *ArkServiceDeleteNostrRecipientParams, opts ...ClientOption) (*ArkServiceDeleteNostrRecipientOK, error)

	ArkServiceGetBoardingAddress(params *ArkServiceGetBoardingAddressParams, opts ...ClientOption) (*ArkServiceGetBoardingAddressOK, error)

	ArkServiceGetEventStream(params *ArkServiceGetEventStreamParams, opts ...ClientOption) (*ArkServiceGetEventStreamOK, error)

	ArkServiceGetInfo(params *ArkServiceGetInfoParams, opts ...ClientOption) (*ArkServiceGetInfoOK, error)

	ArkServiceGetTransactionsStream(params *ArkServiceGetTransactionsStreamParams, opts ...ClientOption) (*ArkServiceGetTransactionsStreamOK, error)

	ArkServicePing(params *ArkServicePingParams, opts ...ClientOption) (*ArkServicePingOK, error)

	ArkServiceRegisterInputsForNextRound(params *ArkServiceRegisterInputsForNextRoundParams, opts ...ClientOption) (*ArkServiceRegisterInputsForNextRoundOK, error)

	ArkServiceRegisterOutputsForNextRound(params *ArkServiceRegisterOutputsForNextRoundParams, opts ...ClientOption) (*ArkServiceRegisterOutputsForNextRoundOK, error)

	ArkServiceSetNostrRecipient(params *ArkServiceSetNostrRecipientParams, opts ...ClientOption) (*ArkServiceSetNostrRecipientOK, error)

	ArkServiceSubmitRedeemTx(params *ArkServiceSubmitRedeemTxParams, opts ...ClientOption) (*ArkServiceSubmitRedeemTxOK, error)

	ArkServiceSubmitSignedForfeitTxs(params *ArkServiceSubmitSignedForfeitTxsParams, opts ...ClientOption) (*ArkServiceSubmitSignedForfeitTxsOK, error)

	ArkServiceSubmitTreeNonces(params *ArkServiceSubmitTreeNoncesParams, opts ...ClientOption) (*ArkServiceSubmitTreeNoncesOK, error)

	ArkServiceSubmitTreeSignatures(params *ArkServiceSubmitTreeSignaturesParams, opts ...ClientOption) (*ArkServiceSubmitTreeSignaturesOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
ArkServiceDeleteNostrRecipient ark service delete nostr recipient API
*/
func (a *Client) ArkServiceDeleteNostrRecipient(params *ArkServiceDeleteNostrRecipientParams, opts ...ClientOption) (*ArkServiceDeleteNostrRecipientOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceDeleteNostrRecipientParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_DeleteNostrRecipient",
		Method:             "POST",
		PathPattern:        "/v1/vtxo/nostr/delete",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceDeleteNostrRecipientReader{formats: a.formats},
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
	success, ok := result.(*ArkServiceDeleteNostrRecipientOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceDeleteNostrRecipientDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
ArkServiceGetBoardingAddress ark service get boarding address API
*/
func (a *Client) ArkServiceGetBoardingAddress(params *ArkServiceGetBoardingAddressParams, opts ...ClientOption) (*ArkServiceGetBoardingAddressOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceGetBoardingAddressParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_GetBoardingAddress",
		Method:             "POST",
		PathPattern:        "/v1/boarding",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceGetBoardingAddressReader{formats: a.formats},
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
	success, ok := result.(*ArkServiceGetBoardingAddressOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceGetBoardingAddressDefault)
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
ArkServiceGetTransactionsStream ark service get transactions stream API
*/
func (a *Client) ArkServiceGetTransactionsStream(params *ArkServiceGetTransactionsStreamParams, opts ...ClientOption) (*ArkServiceGetTransactionsStreamOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceGetTransactionsStreamParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_GetTransactionsStream",
		Method:             "GET",
		PathPattern:        "/v1/transactions",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceGetTransactionsStreamReader{formats: a.formats},
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
	success, ok := result.(*ArkServiceGetTransactionsStreamOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceGetTransactionsStreamDefault)
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
		PathPattern:        "/v1/round/ping/{requestId}",
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
ArkServiceRegisterInputsForNextRound ark service register inputs for next round API
*/
func (a *Client) ArkServiceRegisterInputsForNextRound(params *ArkServiceRegisterInputsForNextRoundParams, opts ...ClientOption) (*ArkServiceRegisterInputsForNextRoundOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceRegisterInputsForNextRoundParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_RegisterInputsForNextRound",
		Method:             "POST",
		PathPattern:        "/v1/round/registerInputs",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceRegisterInputsForNextRoundReader{formats: a.formats},
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
	success, ok := result.(*ArkServiceRegisterInputsForNextRoundOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceRegisterInputsForNextRoundDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
ArkServiceRegisterOutputsForNextRound ark service register outputs for next round API
*/
func (a *Client) ArkServiceRegisterOutputsForNextRound(params *ArkServiceRegisterOutputsForNextRoundParams, opts ...ClientOption) (*ArkServiceRegisterOutputsForNextRoundOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceRegisterOutputsForNextRoundParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_RegisterOutputsForNextRound",
		Method:             "POST",
		PathPattern:        "/v1/round/registerOutputs",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceRegisterOutputsForNextRoundReader{formats: a.formats},
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
	success, ok := result.(*ArkServiceRegisterOutputsForNextRoundOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceRegisterOutputsForNextRoundDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
ArkServiceSetNostrRecipient ark service set nostr recipient API
*/
func (a *Client) ArkServiceSetNostrRecipient(params *ArkServiceSetNostrRecipientParams, opts ...ClientOption) (*ArkServiceSetNostrRecipientOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceSetNostrRecipientParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_SetNostrRecipient",
		Method:             "POST",
		PathPattern:        "/v1/vtxo/nostr",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceSetNostrRecipientReader{formats: a.formats},
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
	success, ok := result.(*ArkServiceSetNostrRecipientOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceSetNostrRecipientDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
ArkServiceSubmitRedeemTx ark service submit redeem tx API
*/
func (a *Client) ArkServiceSubmitRedeemTx(params *ArkServiceSubmitRedeemTxParams, opts ...ClientOption) (*ArkServiceSubmitRedeemTxOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceSubmitRedeemTxParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_SubmitRedeemTx",
		Method:             "POST",
		PathPattern:        "/v1/redeem-tx",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceSubmitRedeemTxReader{formats: a.formats},
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
	success, ok := result.(*ArkServiceSubmitRedeemTxOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceSubmitRedeemTxDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
ArkServiceSubmitSignedForfeitTxs ark service submit signed forfeit txs API
*/
func (a *Client) ArkServiceSubmitSignedForfeitTxs(params *ArkServiceSubmitSignedForfeitTxsParams, opts ...ClientOption) (*ArkServiceSubmitSignedForfeitTxsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceSubmitSignedForfeitTxsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_SubmitSignedForfeitTxs",
		Method:             "POST",
		PathPattern:        "/v1/round/submitForfeitTxs",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceSubmitSignedForfeitTxsReader{formats: a.formats},
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
	success, ok := result.(*ArkServiceSubmitSignedForfeitTxsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceSubmitSignedForfeitTxsDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
ArkServiceSubmitTreeNonces ark service submit tree nonces API
*/
func (a *Client) ArkServiceSubmitTreeNonces(params *ArkServiceSubmitTreeNoncesParams, opts ...ClientOption) (*ArkServiceSubmitTreeNoncesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceSubmitTreeNoncesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_SubmitTreeNonces",
		Method:             "POST",
		PathPattern:        "/v1/round/tree/submitNonces",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceSubmitTreeNoncesReader{formats: a.formats},
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
	success, ok := result.(*ArkServiceSubmitTreeNoncesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceSubmitTreeNoncesDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
ArkServiceSubmitTreeSignatures ark service submit tree signatures API
*/
func (a *Client) ArkServiceSubmitTreeSignatures(params *ArkServiceSubmitTreeSignaturesParams, opts ...ClientOption) (*ArkServiceSubmitTreeSignaturesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceSubmitTreeSignaturesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ArkService_SubmitTreeSignatures",
		Method:             "POST",
		PathPattern:        "/v1/round/tree/submitSignatures",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceSubmitTreeSignaturesReader{formats: a.formats},
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
	success, ok := result.(*ArkServiceSubmitTreeSignaturesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*ArkServiceSubmitTreeSignaturesDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
