// Code generated by go-swagger; DO NOT EDIT.

package ark_service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/ark-network/ark-sdk/rest/service/models"
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

/*ArkServiceRegisterPaymentOK handles this case with default header values.

A successful response.
*/
type ArkServiceRegisterPaymentOK struct {
	Payload *models.V1RegisterPaymentResponse
}

func (o *ArkServiceRegisterPaymentOK) Error() string {
	return fmt.Sprintf("[POST /v1/payment/register][%d] arkServiceRegisterPaymentOK  %+v", 200, o.Payload)
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

/*ArkServiceRegisterPaymentDefault handles this case with default header values.

An unexpected error response.
*/
type ArkServiceRegisterPaymentDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// Code gets the status code for the ark service register payment default response
func (o *ArkServiceRegisterPaymentDefault) Code() int {
	return o._statusCode
}

func (o *ArkServiceRegisterPaymentDefault) Error() string {
	return fmt.Sprintf("[POST /v1/payment/register][%d] ArkService_RegisterPayment default  %+v", o._statusCode, o.Payload)
}

func (o *ArkServiceRegisterPaymentDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
