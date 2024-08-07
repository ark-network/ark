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

// ArkServiceGetRoundByIDReader is a Reader for the ArkServiceGetRoundByID structure.
type ArkServiceGetRoundByIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ArkServiceGetRoundByIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewArkServiceGetRoundByIDOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewArkServiceGetRoundByIDDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewArkServiceGetRoundByIDOK creates a ArkServiceGetRoundByIDOK with default headers values
func NewArkServiceGetRoundByIDOK() *ArkServiceGetRoundByIDOK {
	return &ArkServiceGetRoundByIDOK{}
}

/*
ArkServiceGetRoundByIDOK describes a response with status code 200, with default header values.

A successful response.
*/
type ArkServiceGetRoundByIDOK struct {
	Payload *models.V1GetRoundByIDResponse
}

// IsSuccess returns true when this ark service get round by Id o k response has a 2xx status code
func (o *ArkServiceGetRoundByIDOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this ark service get round by Id o k response has a 3xx status code
func (o *ArkServiceGetRoundByIDOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ark service get round by Id o k response has a 4xx status code
func (o *ArkServiceGetRoundByIDOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this ark service get round by Id o k response has a 5xx status code
func (o *ArkServiceGetRoundByIDOK) IsServerError() bool {
	return false
}

// IsCode returns true when this ark service get round by Id o k response a status code equal to that given
func (o *ArkServiceGetRoundByIDOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the ark service get round by Id o k response
func (o *ArkServiceGetRoundByIDOK) Code() int {
	return 200
}

func (o *ArkServiceGetRoundByIDOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/round/id/{id}][%d] arkServiceGetRoundByIdOK %s", 200, payload)
}

func (o *ArkServiceGetRoundByIDOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/round/id/{id}][%d] arkServiceGetRoundByIdOK %s", 200, payload)
}

func (o *ArkServiceGetRoundByIDOK) GetPayload() *models.V1GetRoundByIDResponse {
	return o.Payload
}

func (o *ArkServiceGetRoundByIDOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.V1GetRoundByIDResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewArkServiceGetRoundByIDDefault creates a ArkServiceGetRoundByIDDefault with default headers values
func NewArkServiceGetRoundByIDDefault(code int) *ArkServiceGetRoundByIDDefault {
	return &ArkServiceGetRoundByIDDefault{
		_statusCode: code,
	}
}

/*
ArkServiceGetRoundByIDDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type ArkServiceGetRoundByIDDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this ark service get round by Id default response has a 2xx status code
func (o *ArkServiceGetRoundByIDDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this ark service get round by Id default response has a 3xx status code
func (o *ArkServiceGetRoundByIDDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this ark service get round by Id default response has a 4xx status code
func (o *ArkServiceGetRoundByIDDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this ark service get round by Id default response has a 5xx status code
func (o *ArkServiceGetRoundByIDDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this ark service get round by Id default response a status code equal to that given
func (o *ArkServiceGetRoundByIDDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the ark service get round by Id default response
func (o *ArkServiceGetRoundByIDDefault) Code() int {
	return o._statusCode
}

func (o *ArkServiceGetRoundByIDDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/round/id/{id}][%d] ArkService_GetRoundById default %s", o._statusCode, payload)
}

func (o *ArkServiceGetRoundByIDDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/round/id/{id}][%d] ArkService_GetRoundById default %s", o._statusCode, payload)
}

func (o *ArkServiceGetRoundByIDDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *ArkServiceGetRoundByIDDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
