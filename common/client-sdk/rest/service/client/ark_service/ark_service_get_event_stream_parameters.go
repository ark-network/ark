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

	strfmt "github.com/go-openapi/strfmt"
)

// NewArkServiceGetEventStreamParams creates a new ArkServiceGetEventStreamParams object
// with the default values initialized.
func NewArkServiceGetEventStreamParams() *ArkServiceGetEventStreamParams {

	return &ArkServiceGetEventStreamParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewArkServiceGetEventStreamParamsWithTimeout creates a new ArkServiceGetEventStreamParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewArkServiceGetEventStreamParamsWithTimeout(timeout time.Duration) *ArkServiceGetEventStreamParams {

	return &ArkServiceGetEventStreamParams{

		timeout: timeout,
	}
}

// NewArkServiceGetEventStreamParamsWithContext creates a new ArkServiceGetEventStreamParams object
// with the default values initialized, and the ability to set a context for a request
func NewArkServiceGetEventStreamParamsWithContext(ctx context.Context) *ArkServiceGetEventStreamParams {

	return &ArkServiceGetEventStreamParams{

		Context: ctx,
	}
}

// NewArkServiceGetEventStreamParamsWithHTTPClient creates a new ArkServiceGetEventStreamParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewArkServiceGetEventStreamParamsWithHTTPClient(client *http.Client) *ArkServiceGetEventStreamParams {

	return &ArkServiceGetEventStreamParams{
		HTTPClient: client,
	}
}

/*ArkServiceGetEventStreamParams contains all the parameters to send to the API endpoint
for the ark service get event stream operation typically these are written to a http.Request
*/
type ArkServiceGetEventStreamParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the ark service get event stream params
func (o *ArkServiceGetEventStreamParams) WithTimeout(timeout time.Duration) *ArkServiceGetEventStreamParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the ark service get event stream params
func (o *ArkServiceGetEventStreamParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the ark service get event stream params
func (o *ArkServiceGetEventStreamParams) WithContext(ctx context.Context) *ArkServiceGetEventStreamParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the ark service get event stream params
func (o *ArkServiceGetEventStreamParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the ark service get event stream params
func (o *ArkServiceGetEventStreamParams) WithHTTPClient(client *http.Client) *ArkServiceGetEventStreamParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the ark service get event stream params
func (o *ArkServiceGetEventStreamParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *ArkServiceGetEventStreamParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
