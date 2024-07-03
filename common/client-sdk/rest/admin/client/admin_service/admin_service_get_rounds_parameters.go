// Code generated by go-swagger; DO NOT EDIT.

package admin_service

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

	models "github.com/ark-network/ark/common/client-sdk/rest/admin/models"
)

// NewAdminServiceGetRoundsParams creates a new AdminServiceGetRoundsParams object
// with the default values initialized.
func NewAdminServiceGetRoundsParams() *AdminServiceGetRoundsParams {
	var ()
	return &AdminServiceGetRoundsParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewAdminServiceGetRoundsParamsWithTimeout creates a new AdminServiceGetRoundsParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewAdminServiceGetRoundsParamsWithTimeout(timeout time.Duration) *AdminServiceGetRoundsParams {
	var ()
	return &AdminServiceGetRoundsParams{

		timeout: timeout,
	}
}

// NewAdminServiceGetRoundsParamsWithContext creates a new AdminServiceGetRoundsParams object
// with the default values initialized, and the ability to set a context for a request
func NewAdminServiceGetRoundsParamsWithContext(ctx context.Context) *AdminServiceGetRoundsParams {
	var ()
	return &AdminServiceGetRoundsParams{

		Context: ctx,
	}
}

// NewAdminServiceGetRoundsParamsWithHTTPClient creates a new AdminServiceGetRoundsParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewAdminServiceGetRoundsParamsWithHTTPClient(client *http.Client) *AdminServiceGetRoundsParams {
	var ()
	return &AdminServiceGetRoundsParams{
		HTTPClient: client,
	}
}

/*AdminServiceGetRoundsParams contains all the parameters to send to the API endpoint
for the admin service get rounds operation typically these are written to a http.Request
*/
type AdminServiceGetRoundsParams struct {

	/*Body*/
	Body *models.V1GetRoundsRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the admin service get rounds params
func (o *AdminServiceGetRoundsParams) WithTimeout(timeout time.Duration) *AdminServiceGetRoundsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the admin service get rounds params
func (o *AdminServiceGetRoundsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the admin service get rounds params
func (o *AdminServiceGetRoundsParams) WithContext(ctx context.Context) *AdminServiceGetRoundsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the admin service get rounds params
func (o *AdminServiceGetRoundsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the admin service get rounds params
func (o *AdminServiceGetRoundsParams) WithHTTPClient(client *http.Client) *AdminServiceGetRoundsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the admin service get rounds params
func (o *AdminServiceGetRoundsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the admin service get rounds params
func (o *AdminServiceGetRoundsParams) WithBody(body *models.V1GetRoundsRequest) *AdminServiceGetRoundsParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the admin service get rounds params
func (o *AdminServiceGetRoundsParams) SetBody(body *models.V1GetRoundsRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *AdminServiceGetRoundsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
