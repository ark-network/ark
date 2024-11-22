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

// ArkServiceCompletePaymentReader is a Reader for the ArkServiceCompletePayment structure.
type ArkServiceCompletePaymentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ArkServiceCompletePaymentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewArkServiceCompletePaymentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewArkServiceCompletePaymentDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewArkServiceCompletePaymentOK creates a ArkServiceCompletePaymentOK with default headers values
func NewArkServiceCompletePaymentOK() *ArkServiceCompletePaymentOK {
	return &ArkServiceCompletePaymentOK{}
}

/*
ArkServiceCompletePaymentOK describes a response with status code 200, with default header values.

A successful response.
*/
type ArkServiceCompletePaymentOK struct {
	Payload *models.V1CompletePaymentResponse
}

// IsSuccess returns true when this ark service complete payment o k response has a 2xx status code
func (o *ArkServiceCompletePaymentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this ark service complete payment o k response has a 3xx status code
func (o *ArkServiceCompletePaymentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ark service complete payment o k response has a 4xx status code
func (o *ArkServiceCompletePaymentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this ark service complete payment o k response has a 5xx status code
func (o *ArkServiceCompletePaymentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this ark service complete payment o k response a status code equal to that given
func (o *ArkServiceCompletePaymentOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the ark service complete payment o k response
func (o *ArkServiceCompletePaymentOK) Code() int {
	return 200
}

func (o *ArkServiceCompletePaymentOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/payment/complete][%d] arkServiceCompletePaymentOK %s", 200, payload)
}

func (o *ArkServiceCompletePaymentOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/payment/complete][%d] arkServiceCompletePaymentOK %s", 200, payload)
}

func (o *ArkServiceCompletePaymentOK) GetPayload() *models.V1CompletePaymentResponse {
	return o.Payload
}

func (o *ArkServiceCompletePaymentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.V1CompletePaymentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewArkServiceCompletePaymentDefault creates a ArkServiceCompletePaymentDefault with default headers values
func NewArkServiceCompletePaymentDefault(code int) *ArkServiceCompletePaymentDefault {
	return &ArkServiceCompletePaymentDefault{
		_statusCode: code,
	}
}

/*
ArkServiceCompletePaymentDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type ArkServiceCompletePaymentDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this ark service complete payment default response has a 2xx status code
func (o *ArkServiceCompletePaymentDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this ark service complete payment default response has a 3xx status code
func (o *ArkServiceCompletePaymentDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this ark service complete payment default response has a 4xx status code
func (o *ArkServiceCompletePaymentDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this ark service complete payment default response has a 5xx status code
func (o *ArkServiceCompletePaymentDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this ark service complete payment default response a status code equal to that given
func (o *ArkServiceCompletePaymentDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the ark service complete payment default response
func (o *ArkServiceCompletePaymentDefault) Code() int {
	return o._statusCode
}

func (o *ArkServiceCompletePaymentDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/payment/complete][%d] ArkService_CompletePayment default %s", o._statusCode, payload)
}

func (o *ArkServiceCompletePaymentDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/payment/complete][%d] ArkService_CompletePayment default %s", o._statusCode, payload)
}

func (o *ArkServiceCompletePaymentDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *ArkServiceCompletePaymentDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
