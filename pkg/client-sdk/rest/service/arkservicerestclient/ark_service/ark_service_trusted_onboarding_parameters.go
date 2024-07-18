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

	models "github.com/ark-network/ark-sdk/rest/service/models"
)

// NewArkServiceTrustedOnboardingParams creates a new ArkServiceTrustedOnboardingParams object
// with the default values initialized.
func NewArkServiceTrustedOnboardingParams() *ArkServiceTrustedOnboardingParams {
	var ()
	return &ArkServiceTrustedOnboardingParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewArkServiceTrustedOnboardingParamsWithTimeout creates a new ArkServiceTrustedOnboardingParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewArkServiceTrustedOnboardingParamsWithTimeout(timeout time.Duration) *ArkServiceTrustedOnboardingParams {
	var ()
	return &ArkServiceTrustedOnboardingParams{

		timeout: timeout,
	}
}

// NewArkServiceTrustedOnboardingParamsWithContext creates a new ArkServiceTrustedOnboardingParams object
// with the default values initialized, and the ability to set a context for a request
func NewArkServiceTrustedOnboardingParamsWithContext(ctx context.Context) *ArkServiceTrustedOnboardingParams {
	var ()
	return &ArkServiceTrustedOnboardingParams{

		Context: ctx,
	}
}

// NewArkServiceTrustedOnboardingParamsWithHTTPClient creates a new ArkServiceTrustedOnboardingParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewArkServiceTrustedOnboardingParamsWithHTTPClient(client *http.Client) *ArkServiceTrustedOnboardingParams {
	var ()
	return &ArkServiceTrustedOnboardingParams{
		HTTPClient: client,
	}
}

/*ArkServiceTrustedOnboardingParams contains all the parameters to send to the API endpoint
for the ark service trusted onboarding operation typically these are written to a http.Request
*/
type ArkServiceTrustedOnboardingParams struct {

	/*Body*/
	Body *models.V1TrustedOnboardingRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the ark service trusted onboarding params
func (o *ArkServiceTrustedOnboardingParams) WithTimeout(timeout time.Duration) *ArkServiceTrustedOnboardingParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the ark service trusted onboarding params
func (o *ArkServiceTrustedOnboardingParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the ark service trusted onboarding params
func (o *ArkServiceTrustedOnboardingParams) WithContext(ctx context.Context) *ArkServiceTrustedOnboardingParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the ark service trusted onboarding params
func (o *ArkServiceTrustedOnboardingParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the ark service trusted onboarding params
func (o *ArkServiceTrustedOnboardingParams) WithHTTPClient(client *http.Client) *ArkServiceTrustedOnboardingParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the ark service trusted onboarding params
func (o *ArkServiceTrustedOnboardingParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the ark service trusted onboarding params
func (o *ArkServiceTrustedOnboardingParams) WithBody(body *models.V1TrustedOnboardingRequest) *ArkServiceTrustedOnboardingParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the ark service trusted onboarding params
func (o *ArkServiceTrustedOnboardingParams) SetBody(body *models.V1TrustedOnboardingRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *ArkServiceTrustedOnboardingParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
