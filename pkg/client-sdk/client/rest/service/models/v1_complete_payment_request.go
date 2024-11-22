// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1CompletePaymentRequest v1 complete payment request
//
// swagger:model v1CompletePaymentRequest
type V1CompletePaymentRequest struct {

	// redeem tx
	RedeemTx string `json:"redeemTx,omitempty"`
}

// Validate validates this v1 complete payment request
func (m *V1CompletePaymentRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this v1 complete payment request based on context it is used
func (m *V1CompletePaymentRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *V1CompletePaymentRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1CompletePaymentRequest) UnmarshalBinary(b []byte) error {
	var res V1CompletePaymentRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
