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

	"github.com/ark-network/ark-sdk/client/rest/service/models"
)

// ArkServiceRegisterPaymentReader is a Reader for the ArkServiceRegisterPayment structure.
type ArkServiceRegisterPaymentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ArkServiceRegisterPaymentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewArkServiceRegisterPaymentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewArkServiceRegisterPaymentDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewArkServiceRegisterPaymentOK creates a ArkServiceRegisterPaymentOK with default headers values
func NewArkServiceRegisterPaymentOK() *ArkServiceRegisterPaymentOK {
	return &ArkServiceRegisterPaymentOK{}
}

/*
ArkServiceRegisterPaymentOK describes a response with status code 200, with default header values.

A successful response.
*/
type ArkServiceRegisterPaymentOK struct {
	Payload *models.V1RegisterPaymentResponse
}

// IsSuccess returns true when this ark service register payment o k response has a 2xx status code
func (o *ArkServiceRegisterPaymentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this ark service register payment o k response has a 3xx status code
func (o *ArkServiceRegisterPaymentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ark service register payment o k response has a 4xx status code
func (o *ArkServiceRegisterPaymentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this ark service register payment o k response has a 5xx status code
func (o *ArkServiceRegisterPaymentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this ark service register payment o k response a status code equal to that given
func (o *ArkServiceRegisterPaymentOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the ark service register payment o k response
func (o *ArkServiceRegisterPaymentOK) Code() int {
	return 200
}

func (o *ArkServiceRegisterPaymentOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/payment/register][%d] arkServiceRegisterPaymentOK %s", 200, payload)
}

func (o *ArkServiceRegisterPaymentOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/payment/register][%d] arkServiceRegisterPaymentOK %s", 200, payload)
}

func (o *ArkServiceRegisterPaymentOK) GetPayload() *models.V1RegisterPaymentResponse {
	return o.Payload
}

func (o *ArkServiceRegisterPaymentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.V1RegisterPaymentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewArkServiceRegisterPaymentDefault creates a ArkServiceRegisterPaymentDefault with default headers values
func NewArkServiceRegisterPaymentDefault(code int) *ArkServiceRegisterPaymentDefault {
	return &ArkServiceRegisterPaymentDefault{
		_statusCode: code,
	}
}

/*
ArkServiceRegisterPaymentDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type ArkServiceRegisterPaymentDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this ark service register payment default response has a 2xx status code
func (o *ArkServiceRegisterPaymentDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this ark service register payment default response has a 3xx status code
func (o *ArkServiceRegisterPaymentDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this ark service register payment default response has a 4xx status code
func (o *ArkServiceRegisterPaymentDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this ark service register payment default response has a 5xx status code
func (o *ArkServiceRegisterPaymentDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this ark service register payment default response a status code equal to that given
func (o *ArkServiceRegisterPaymentDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the ark service register payment default response
func (o *ArkServiceRegisterPaymentDefault) Code() int {
	return o._statusCode
}

func (o *ArkServiceRegisterPaymentDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/payment/register][%d] ArkService_RegisterPayment default %s", o._statusCode, payload)
}

func (o *ArkServiceRegisterPaymentDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/payment/register][%d] ArkService_RegisterPayment default %s", o._statusCode, payload)
}

func (o *ArkServiceRegisterPaymentDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *ArkServiceRegisterPaymentDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
