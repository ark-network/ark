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

// NewArkServiceReverseBoardingAddressParams creates a new ArkServiceReverseBoardingAddressParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewArkServiceReverseBoardingAddressParams() *ArkServiceReverseBoardingAddressParams {
	return &ArkServiceReverseBoardingAddressParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewArkServiceReverseBoardingAddressParamsWithTimeout creates a new ArkServiceReverseBoardingAddressParams object
// with the ability to set a timeout on a request.
func NewArkServiceReverseBoardingAddressParamsWithTimeout(timeout time.Duration) *ArkServiceReverseBoardingAddressParams {
	return &ArkServiceReverseBoardingAddressParams{
		timeout: timeout,
	}
}

// NewArkServiceReverseBoardingAddressParamsWithContext creates a new ArkServiceReverseBoardingAddressParams object
// with the ability to set a context for a request.
func NewArkServiceReverseBoardingAddressParamsWithContext(ctx context.Context) *ArkServiceReverseBoardingAddressParams {
	return &ArkServiceReverseBoardingAddressParams{
		Context: ctx,
	}
}

// NewArkServiceReverseBoardingAddressParamsWithHTTPClient creates a new ArkServiceReverseBoardingAddressParams object
// with the ability to set a custom HTTPClient for a request.
func NewArkServiceReverseBoardingAddressParamsWithHTTPClient(client *http.Client) *ArkServiceReverseBoardingAddressParams {
	return &ArkServiceReverseBoardingAddressParams{
		HTTPClient: client,
	}
}

/*
ArkServiceReverseBoardingAddressParams contains all the parameters to send to the API endpoint

	for the ark service reverse boarding address operation.

	Typically these are written to a http.Request.
*/
type ArkServiceReverseBoardingAddressParams struct {

	// Body.
	Body *models.V1ReverseBoardingAddressRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the ark service reverse boarding address params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ArkServiceReverseBoardingAddressParams) WithDefaults() *ArkServiceReverseBoardingAddressParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the ark service reverse boarding address params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ArkServiceReverseBoardingAddressParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the ark service reverse boarding address params
func (o *ArkServiceReverseBoardingAddressParams) WithTimeout(timeout time.Duration) *ArkServiceReverseBoardingAddressParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the ark service reverse boarding address params
func (o *ArkServiceReverseBoardingAddressParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the ark service reverse boarding address params
func (o *ArkServiceReverseBoardingAddressParams) WithContext(ctx context.Context) *ArkServiceReverseBoardingAddressParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the ark service reverse boarding address params
func (o *ArkServiceReverseBoardingAddressParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the ark service reverse boarding address params
func (o *ArkServiceReverseBoardingAddressParams) WithHTTPClient(client *http.Client) *ArkServiceReverseBoardingAddressParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the ark service reverse boarding address params
func (o *ArkServiceReverseBoardingAddressParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the ark service reverse boarding address params
func (o *ArkServiceReverseBoardingAddressParams) WithBody(body *models.V1ReverseBoardingAddressRequest) *ArkServiceReverseBoardingAddressParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the ark service reverse boarding address params
func (o *ArkServiceReverseBoardingAddressParams) SetBody(body *models.V1ReverseBoardingAddressRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *ArkServiceReverseBoardingAddressParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
