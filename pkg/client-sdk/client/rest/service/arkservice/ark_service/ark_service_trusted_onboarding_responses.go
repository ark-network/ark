// Code generated by go-swagger; DO NOT EDIT.

package ark_service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/ark-network/ark/pkg/client-sdk/client/rest/service/models"
)

// ArkServiceTrustedOnboardingReader is a Reader for the ArkServiceTrustedOnboarding structure.
type ArkServiceTrustedOnboardingReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ArkServiceTrustedOnboardingReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewArkServiceTrustedOnboardingOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewArkServiceTrustedOnboardingDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewArkServiceTrustedOnboardingOK creates a ArkServiceTrustedOnboardingOK with default headers values
func NewArkServiceTrustedOnboardingOK() *ArkServiceTrustedOnboardingOK {
	return &ArkServiceTrustedOnboardingOK{}
}

/*
ArkServiceTrustedOnboardingOK describes a response with status code 200, with default header values.

A successful response.
*/
type ArkServiceTrustedOnboardingOK struct {
	Payload *models.V1TrustedOnboardingResponse
}

// IsSuccess returns true when this ark service trusted onboarding o k response has a 2xx status code
func (o *ArkServiceTrustedOnboardingOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this ark service trusted onboarding o k response has a 3xx status code
func (o *ArkServiceTrustedOnboardingOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ark service trusted onboarding o k response has a 4xx status code
func (o *ArkServiceTrustedOnboardingOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this ark service trusted onboarding o k response has a 5xx status code
func (o *ArkServiceTrustedOnboardingOK) IsServerError() bool {
	return false
}

// IsCode returns true when this ark service trusted onboarding o k response a status code equal to that given
func (o *ArkServiceTrustedOnboardingOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the ark service trusted onboarding o k response
func (o *ArkServiceTrustedOnboardingOK) Code() int {
	return 200
}

func (o *ArkServiceTrustedOnboardingOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/onboard/address][%d] arkServiceTrustedOnboardingOK %s", 200, payload)
}

func (o *ArkServiceTrustedOnboardingOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/onboard/address][%d] arkServiceTrustedOnboardingOK %s", 200, payload)
}

func (o *ArkServiceTrustedOnboardingOK) GetPayload() *models.V1TrustedOnboardingResponse {
	return o.Payload
}

func (o *ArkServiceTrustedOnboardingOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.V1TrustedOnboardingResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewArkServiceTrustedOnboardingDefault creates a ArkServiceTrustedOnboardingDefault with default headers values
func NewArkServiceTrustedOnboardingDefault(code int) *ArkServiceTrustedOnboardingDefault {
	return &ArkServiceTrustedOnboardingDefault{
		_statusCode: code,
	}
}

/*
ArkServiceTrustedOnboardingDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type ArkServiceTrustedOnboardingDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this ark service trusted onboarding default response has a 2xx status code
func (o *ArkServiceTrustedOnboardingDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this ark service trusted onboarding default response has a 3xx status code
func (o *ArkServiceTrustedOnboardingDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this ark service trusted onboarding default response has a 4xx status code
func (o *ArkServiceTrustedOnboardingDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this ark service trusted onboarding default response has a 5xx status code
func (o *ArkServiceTrustedOnboardingDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this ark service trusted onboarding default response a status code equal to that given
func (o *ArkServiceTrustedOnboardingDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the ark service trusted onboarding default response
func (o *ArkServiceTrustedOnboardingDefault) Code() int {
	return o._statusCode
}

func (o *ArkServiceTrustedOnboardingDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/onboard/address][%d] ArkService_TrustedOnboarding default %s", o._statusCode, payload)
}

func (o *ArkServiceTrustedOnboardingDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/onboard/address][%d] ArkService_TrustedOnboarding default %s", o._statusCode, payload)
}

func (o *ArkServiceTrustedOnboardingDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *ArkServiceTrustedOnboardingDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
