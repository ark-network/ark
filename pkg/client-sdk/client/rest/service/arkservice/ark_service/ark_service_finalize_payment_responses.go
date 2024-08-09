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

// ArkServiceFinalizePaymentReader is a Reader for the ArkServiceFinalizePayment structure.
type ArkServiceFinalizePaymentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ArkServiceFinalizePaymentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewArkServiceFinalizePaymentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewArkServiceFinalizePaymentDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewArkServiceFinalizePaymentOK creates a ArkServiceFinalizePaymentOK with default headers values
func NewArkServiceFinalizePaymentOK() *ArkServiceFinalizePaymentOK {
	return &ArkServiceFinalizePaymentOK{}
}

/*
ArkServiceFinalizePaymentOK describes a response with status code 200, with default header values.

A successful response.
*/
type ArkServiceFinalizePaymentOK struct {
	Payload models.V1FinalizePaymentResponse
}

// IsSuccess returns true when this ark service finalize payment o k response has a 2xx status code
func (o *ArkServiceFinalizePaymentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this ark service finalize payment o k response has a 3xx status code
func (o *ArkServiceFinalizePaymentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ark service finalize payment o k response has a 4xx status code
func (o *ArkServiceFinalizePaymentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this ark service finalize payment o k response has a 5xx status code
func (o *ArkServiceFinalizePaymentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this ark service finalize payment o k response a status code equal to that given
func (o *ArkServiceFinalizePaymentOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the ark service finalize payment o k response
func (o *ArkServiceFinalizePaymentOK) Code() int {
	return 200
}

func (o *ArkServiceFinalizePaymentOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/payment/finalize][%d] arkServiceFinalizePaymentOK %s", 200, payload)
}

func (o *ArkServiceFinalizePaymentOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/payment/finalize][%d] arkServiceFinalizePaymentOK %s", 200, payload)
}

func (o *ArkServiceFinalizePaymentOK) GetPayload() models.V1FinalizePaymentResponse {
	return o.Payload
}

func (o *ArkServiceFinalizePaymentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewArkServiceFinalizePaymentDefault creates a ArkServiceFinalizePaymentDefault with default headers values
func NewArkServiceFinalizePaymentDefault(code int) *ArkServiceFinalizePaymentDefault {
	return &ArkServiceFinalizePaymentDefault{
		_statusCode: code,
	}
}

/*
ArkServiceFinalizePaymentDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type ArkServiceFinalizePaymentDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this ark service finalize payment default response has a 2xx status code
func (o *ArkServiceFinalizePaymentDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this ark service finalize payment default response has a 3xx status code
func (o *ArkServiceFinalizePaymentDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this ark service finalize payment default response has a 4xx status code
func (o *ArkServiceFinalizePaymentDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this ark service finalize payment default response has a 5xx status code
func (o *ArkServiceFinalizePaymentDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this ark service finalize payment default response a status code equal to that given
func (o *ArkServiceFinalizePaymentDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the ark service finalize payment default response
func (o *ArkServiceFinalizePaymentDefault) Code() int {
	return o._statusCode
}

func (o *ArkServiceFinalizePaymentDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/payment/finalize][%d] ArkService_FinalizePayment default %s", o._statusCode, payload)
}

func (o *ArkServiceFinalizePaymentDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/payment/finalize][%d] ArkService_FinalizePayment default %s", o._statusCode, payload)
}

func (o *ArkServiceFinalizePaymentDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *ArkServiceFinalizePaymentDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
