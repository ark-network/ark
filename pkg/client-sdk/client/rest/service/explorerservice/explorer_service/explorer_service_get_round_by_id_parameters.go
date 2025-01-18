// Code generated by go-swagger; DO NOT EDIT.

package explorer_service

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
)

// NewExplorerServiceGetRoundByIDParams creates a new ExplorerServiceGetRoundByIDParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewExplorerServiceGetRoundByIDParams() *ExplorerServiceGetRoundByIDParams {
	return &ExplorerServiceGetRoundByIDParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewExplorerServiceGetRoundByIDParamsWithTimeout creates a new ExplorerServiceGetRoundByIDParams object
// with the ability to set a timeout on a request.
func NewExplorerServiceGetRoundByIDParamsWithTimeout(timeout time.Duration) *ExplorerServiceGetRoundByIDParams {
	return &ExplorerServiceGetRoundByIDParams{
		timeout: timeout,
	}
}

// NewExplorerServiceGetRoundByIDParamsWithContext creates a new ExplorerServiceGetRoundByIDParams object
// with the ability to set a context for a request.
func NewExplorerServiceGetRoundByIDParamsWithContext(ctx context.Context) *ExplorerServiceGetRoundByIDParams {
	return &ExplorerServiceGetRoundByIDParams{
		Context: ctx,
	}
}

// NewExplorerServiceGetRoundByIDParamsWithHTTPClient creates a new ExplorerServiceGetRoundByIDParams object
// with the ability to set a custom HTTPClient for a request.
func NewExplorerServiceGetRoundByIDParamsWithHTTPClient(client *http.Client) *ExplorerServiceGetRoundByIDParams {
	return &ExplorerServiceGetRoundByIDParams{
		HTTPClient: client,
	}
}

/*
ExplorerServiceGetRoundByIDParams contains all the parameters to send to the API endpoint

	for the explorer service get round by Id operation.

	Typically these are written to a http.Request.
*/
type ExplorerServiceGetRoundByIDParams struct {

	// ID.
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the explorer service get round by Id params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExplorerServiceGetRoundByIDParams) WithDefaults() *ExplorerServiceGetRoundByIDParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the explorer service get round by Id params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExplorerServiceGetRoundByIDParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the explorer service get round by Id params
func (o *ExplorerServiceGetRoundByIDParams) WithTimeout(timeout time.Duration) *ExplorerServiceGetRoundByIDParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the explorer service get round by Id params
func (o *ExplorerServiceGetRoundByIDParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the explorer service get round by Id params
func (o *ExplorerServiceGetRoundByIDParams) WithContext(ctx context.Context) *ExplorerServiceGetRoundByIDParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the explorer service get round by Id params
func (o *ExplorerServiceGetRoundByIDParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the explorer service get round by Id params
func (o *ExplorerServiceGetRoundByIDParams) WithHTTPClient(client *http.Client) *ExplorerServiceGetRoundByIDParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the explorer service get round by Id params
func (o *ExplorerServiceGetRoundByIDParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the explorer service get round by Id params
func (o *ExplorerServiceGetRoundByIDParams) WithID(id string) *ExplorerServiceGetRoundByIDParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the explorer service get round by Id params
func (o *ExplorerServiceGetRoundByIDParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *ExplorerServiceGetRoundByIDParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
