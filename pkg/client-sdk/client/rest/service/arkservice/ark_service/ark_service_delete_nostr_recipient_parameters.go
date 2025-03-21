// Code generated by go-swagger; DO NOT EDIT.

package ark_service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/ark-network/ark/pkg/client-sdk/client/rest/service/models"
)

// NewArkServiceDeleteNostrRecipientParams creates a new ArkServiceDeleteNostrRecipientParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewArkServiceDeleteNostrRecipientParams() *ArkServiceDeleteNostrRecipientParams {
	return &ArkServiceDeleteNostrRecipientParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewArkServiceDeleteNostrRecipientParamsWithTimeout creates a new ArkServiceDeleteNostrRecipientParams object
// with the ability to set a timeout on a request.
func NewArkServiceDeleteNostrRecipientParamsWithTimeout(timeout time.Duration) *ArkServiceDeleteNostrRecipientParams {
	return &ArkServiceDeleteNostrRecipientParams{
		timeout: timeout,
	}
}

// NewArkServiceDeleteNostrRecipientParamsWithContext creates a new ArkServiceDeleteNostrRecipientParams object
// with the ability to set a context for a request.
func NewArkServiceDeleteNostrRecipientParamsWithContext(ctx context.Context) *ArkServiceDeleteNostrRecipientParams {
	return &ArkServiceDeleteNostrRecipientParams{
		Context: ctx,
	}
}

// NewArkServiceDeleteNostrRecipientParamsWithHTTPClient creates a new ArkServiceDeleteNostrRecipientParams object
// with the ability to set a custom HTTPClient for a request.
func NewArkServiceDeleteNostrRecipientParamsWithHTTPClient(client *http.Client) *ArkServiceDeleteNostrRecipientParams {
	return &ArkServiceDeleteNostrRecipientParams{
		HTTPClient: client,
	}
}

/*
ArkServiceDeleteNostrRecipientParams contains all the parameters to send to the API endpoint

	for the ark service delete nostr recipient operation.

	Typically these are written to a http.Request.
*/
type ArkServiceDeleteNostrRecipientParams struct {

	// Body.
	Body *models.V1DeleteNostrRecipientRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the ark service delete nostr recipient params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ArkServiceDeleteNostrRecipientParams) WithDefaults() *ArkServiceDeleteNostrRecipientParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the ark service delete nostr recipient params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ArkServiceDeleteNostrRecipientParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the ark service delete nostr recipient params
func (o *ArkServiceDeleteNostrRecipientParams) WithTimeout(timeout time.Duration) *ArkServiceDeleteNostrRecipientParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the ark service delete nostr recipient params
func (o *ArkServiceDeleteNostrRecipientParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the ark service delete nostr recipient params
func (o *ArkServiceDeleteNostrRecipientParams) WithContext(ctx context.Context) *ArkServiceDeleteNostrRecipientParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the ark service delete nostr recipient params
func (o *ArkServiceDeleteNostrRecipientParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the ark service delete nostr recipient params
func (o *ArkServiceDeleteNostrRecipientParams) WithHTTPClient(client *http.Client) *ArkServiceDeleteNostrRecipientParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the ark service delete nostr recipient params
func (o *ArkServiceDeleteNostrRecipientParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the ark service delete nostr recipient params
func (o *ArkServiceDeleteNostrRecipientParams) WithBody(body *models.V1DeleteNostrRecipientRequest) *ArkServiceDeleteNostrRecipientParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the ark service delete nostr recipient params
func (o *ArkServiceDeleteNostrRecipientParams) SetBody(body *models.V1DeleteNostrRecipientRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *ArkServiceDeleteNostrRecipientParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
