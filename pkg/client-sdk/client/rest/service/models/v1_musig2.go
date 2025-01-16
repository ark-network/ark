// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1Musig2 v1 musig2
//
// swagger:model v1Musig2
type V1Musig2 struct {

	// cosigners public keys
	CosignersPublicKeys []string `json:"cosignersPublicKeys"`

	// signing type
	SigningType int64 `json:"signingType,omitempty"`
}

// Validate validates this v1 musig2
func (m *V1Musig2) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this v1 musig2 based on context it is used
func (m *V1Musig2) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *V1Musig2) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1Musig2) UnmarshalBinary(b []byte) error {
	var res V1Musig2
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
