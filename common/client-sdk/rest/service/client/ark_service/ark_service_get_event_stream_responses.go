// Code generated by go-swagger; DO NOT EDIT.

package ark_service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/swag"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/ark-network/ark/common/client-sdk/rest/service/models"
)

// ArkServiceGetEventStreamReader is a Reader for the ArkServiceGetEventStream structure.
type ArkServiceGetEventStreamReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ArkServiceGetEventStreamReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewArkServiceGetEventStreamOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	default:
		result := NewArkServiceGetEventStreamDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewArkServiceGetEventStreamOK creates a ArkServiceGetEventStreamOK with default headers values
func NewArkServiceGetEventStreamOK() *ArkServiceGetEventStreamOK {
	return &ArkServiceGetEventStreamOK{}
}

/*ArkServiceGetEventStreamOK handles this case with default header values.

A successful response.(streaming responses)
*/
type ArkServiceGetEventStreamOK struct {
	Payload *ArkServiceGetEventStreamOKBody
}

func (o *ArkServiceGetEventStreamOK) Error() string {
	return fmt.Sprintf("[GET /v1/events][%d] arkServiceGetEventStreamOK  %+v", 200, o.Payload)
}

func (o *ArkServiceGetEventStreamOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(ArkServiceGetEventStreamOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewArkServiceGetEventStreamDefault creates a ArkServiceGetEventStreamDefault with default headers values
func NewArkServiceGetEventStreamDefault(code int) *ArkServiceGetEventStreamDefault {
	return &ArkServiceGetEventStreamDefault{
		_statusCode: code,
	}
}

/*ArkServiceGetEventStreamDefault handles this case with default header values.

An unexpected error response.
*/
type ArkServiceGetEventStreamDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// Code gets the status code for the ark service get event stream default response
func (o *ArkServiceGetEventStreamDefault) Code() int {
	return o._statusCode
}

func (o *ArkServiceGetEventStreamDefault) Error() string {
	return fmt.Sprintf("[GET /v1/events][%d] ArkService_GetEventStream default  %+v", o._statusCode, o.Payload)
}

func (o *ArkServiceGetEventStreamDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*ArkServiceGetEventStreamOKBody Stream result of v1GetEventStreamResponse
swagger:model ArkServiceGetEventStreamOKBody
*/
type ArkServiceGetEventStreamOKBody struct {

	// error
	Error *models.RPCStatus `json:"error,omitempty"`

	// result
	Result *models.V1GetEventStreamResponse `json:"result,omitempty"`
}

// Validate validates this ark service get event stream o k body
func (o *ArkServiceGetEventStreamOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateError(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateResult(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *ArkServiceGetEventStreamOKBody) validateError(formats strfmt.Registry) error {

	if swag.IsZero(o.Error) { // not required
		return nil
	}

	if o.Error != nil {
		if err := o.Error.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("arkServiceGetEventStreamOK" + "." + "error")
			}
			return err
		}
	}

	return nil
}

func (o *ArkServiceGetEventStreamOKBody) validateResult(formats strfmt.Registry) error {

	if swag.IsZero(o.Result) { // not required
		return nil
	}

	if o.Result != nil {
		if err := o.Result.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("arkServiceGetEventStreamOK" + "." + "result")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *ArkServiceGetEventStreamOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *ArkServiceGetEventStreamOKBody) UnmarshalBinary(b []byte) error {
	var res ArkServiceGetEventStreamOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
