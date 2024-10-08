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

// NewArkServiceSubmitSignedForfeitTransactionsParams creates a new ArkServiceSubmitSignedForfeitTransactionsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewArkServiceSubmitSignedForfeitTransactionsParams() *ArkServiceSubmitSignedForfeitTransactionsParams {
	return &ArkServiceSubmitSignedForfeitTransactionsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewArkServiceSubmitSignedForfeitTransactionsParamsWithTimeout creates a new ArkServiceSubmitSignedForfeitTransactionsParams object
// with the ability to set a timeout on a request.
func NewArkServiceSubmitSignedForfeitTransactionsParamsWithTimeout(timeout time.Duration) *ArkServiceSubmitSignedForfeitTransactionsParams {
	return &ArkServiceSubmitSignedForfeitTransactionsParams{
		timeout: timeout,
	}
}

// NewArkServiceSubmitSignedForfeitTransactionsParamsWithContext creates a new ArkServiceSubmitSignedForfeitTransactionsParams object
// with the ability to set a context for a request.
func NewArkServiceSubmitSignedForfeitTransactionsParamsWithContext(ctx context.Context) *ArkServiceSubmitSignedForfeitTransactionsParams {
	return &ArkServiceSubmitSignedForfeitTransactionsParams{
		Context: ctx,
	}
}

// NewArkServiceSubmitSignedForfeitTransactionsParamsWithHTTPClient creates a new ArkServiceSubmitSignedForfeitTransactionsParams object
// with the ability to set a custom HTTPClient for a request.
func NewArkServiceSubmitSignedForfeitTransactionsParamsWithHTTPClient(client *http.Client) *ArkServiceSubmitSignedForfeitTransactionsParams {
	return &ArkServiceSubmitSignedForfeitTransactionsParams{
		HTTPClient: client,
	}
}

/*
ArkServiceSubmitSignedForfeitTransactionsParams contains all the parameters to send to the API endpoint

	for the ark service submit signed forfeit transactions operation.

	Typically these are written to a http.Request.
*/
type ArkServiceSubmitSignedForfeitTransactionsParams struct {

	// Body.
	Body *models.V1SubmitSignedForfeitTransactionsRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the ark service submit signed forfeit transactions params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ArkServiceSubmitSignedForfeitTransactionsParams) WithDefaults() *ArkServiceSubmitSignedForfeitTransactionsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the ark service submit signed forfeit transactions params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ArkServiceSubmitSignedForfeitTransactionsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the ark service submit signed forfeit transactions params
func (o *ArkServiceSubmitSignedForfeitTransactionsParams) WithTimeout(timeout time.Duration) *ArkServiceSubmitSignedForfeitTransactionsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the ark service submit signed forfeit transactions params
func (o *ArkServiceSubmitSignedForfeitTransactionsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the ark service submit signed forfeit transactions params
func (o *ArkServiceSubmitSignedForfeitTransactionsParams) WithContext(ctx context.Context) *ArkServiceSubmitSignedForfeitTransactionsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the ark service submit signed forfeit transactions params
func (o *ArkServiceSubmitSignedForfeitTransactionsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the ark service submit signed forfeit transactions params
func (o *ArkServiceSubmitSignedForfeitTransactionsParams) WithHTTPClient(client *http.Client) *ArkServiceSubmitSignedForfeitTransactionsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the ark service submit signed forfeit transactions params
func (o *ArkServiceSubmitSignedForfeitTransactionsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the ark service submit signed forfeit transactions params
func (o *ArkServiceSubmitSignedForfeitTransactionsParams) WithBody(body *models.V1SubmitSignedForfeitTransactionsRequest) *ArkServiceSubmitSignedForfeitTransactionsParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the ark service submit signed forfeit transactions params
func (o *ArkServiceSubmitSignedForfeitTransactionsParams) SetBody(body *models.V1SubmitSignedForfeitTransactionsRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *ArkServiceSubmitSignedForfeitTransactionsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
