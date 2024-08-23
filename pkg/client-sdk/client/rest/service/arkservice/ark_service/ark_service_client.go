// Code generated by go-swagger; DO NOT EDIT.

package ark_service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"
)

// New creates a new ark service API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) *Client {
	return &Client{transport: transport, formats: formats}
}

/*
Client for ark service API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

/*
ArkServiceClaimPayment ark service claim payment API
*/
func (a *Client) ArkServiceClaimPayment(params *ArkServiceClaimPaymentParams) (*ArkServiceClaimPaymentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceClaimPaymentParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
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
	})
	if err != nil {
		return nil, err
	}
	return result.(*ArkServiceClaimPaymentOK), nil

}

/*
ArkServiceCompletePayment ark service complete payment API
*/
func (a *Client) ArkServiceCompletePayment(params *ArkServiceCompletePaymentParams) (*ArkServiceCompletePaymentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceCompletePaymentParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "ArkService_CompletePayment",
		Method:             "POST",
		PathPattern:        "/v1/payment/complete",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceCompletePaymentReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*ArkServiceCompletePaymentOK), nil

}

/*
ArkServiceCreatePayment ark service create payment API
*/
func (a *Client) ArkServiceCreatePayment(params *ArkServiceCreatePaymentParams) (*ArkServiceCreatePaymentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceCreatePaymentParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "ArkService_CreatePayment",
		Method:             "POST",
		PathPattern:        "/v1/payment",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ArkServiceCreatePaymentReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*ArkServiceCreatePaymentOK), nil

}

/*
ArkServiceFinalizePayment ark service finalize payment API
*/
func (a *Client) ArkServiceFinalizePayment(params *ArkServiceFinalizePaymentParams) (*ArkServiceFinalizePaymentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceFinalizePaymentParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
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
	})
	if err != nil {
		return nil, err
	}
	return result.(*ArkServiceFinalizePaymentOK), nil

}

/*
ArkServiceGetEventStream ark service get event stream API
*/
func (a *Client) ArkServiceGetEventStream(params *ArkServiceGetEventStreamParams) (*ArkServiceGetEventStreamOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceGetEventStreamParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
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
	})
	if err != nil {
		return nil, err
	}
	return result.(*ArkServiceGetEventStreamOK), nil

}

/*
ArkServiceGetInfo ark service get info API
*/
func (a *Client) ArkServiceGetInfo(params *ArkServiceGetInfoParams) (*ArkServiceGetInfoOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceGetInfoParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
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
	})
	if err != nil {
		return nil, err
	}
	return result.(*ArkServiceGetInfoOK), nil

}

/*
ArkServiceGetRound ts o d o b t c sign tree rpc
*/
func (a *Client) ArkServiceGetRound(params *ArkServiceGetRoundParams) (*ArkServiceGetRoundOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceGetRoundParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
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
	})
	if err != nil {
		return nil, err
	}
	return result.(*ArkServiceGetRoundOK), nil

}

/*
ArkServiceGetRoundByID ark service get round by Id API
*/
func (a *Client) ArkServiceGetRoundByID(params *ArkServiceGetRoundByIDParams) (*ArkServiceGetRoundByIDOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceGetRoundByIDParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
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
	})
	if err != nil {
		return nil, err
	}
	return result.(*ArkServiceGetRoundByIDOK), nil

}

/*
ArkServiceListVtxos ark service list vtxos API
*/
func (a *Client) ArkServiceListVtxos(params *ArkServiceListVtxosParams) (*ArkServiceListVtxosOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceListVtxosParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
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
	})
	if err != nil {
		return nil, err
	}
	return result.(*ArkServiceListVtxosOK), nil

}

/*
ArkServiceOnboard ark service onboard API
*/
func (a *Client) ArkServiceOnboard(params *ArkServiceOnboardParams) (*ArkServiceOnboardOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceOnboardParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
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
	})
	if err != nil {
		return nil, err
	}
	return result.(*ArkServiceOnboardOK), nil

}

/*
ArkServicePing ark service ping API
*/
func (a *Client) ArkServicePing(params *ArkServicePingParams) (*ArkServicePingOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServicePingParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
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
	})
	if err != nil {
		return nil, err
	}
	return result.(*ArkServicePingOK), nil

}

/*
ArkServiceRegisterPayment ark service register payment API
*/
func (a *Client) ArkServiceRegisterPayment(params *ArkServiceRegisterPaymentParams) (*ArkServiceRegisterPaymentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewArkServiceRegisterPaymentParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
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
	})
	if err != nil {
		return nil, err
	}
	return result.(*ArkServiceRegisterPaymentOK), nil

}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
