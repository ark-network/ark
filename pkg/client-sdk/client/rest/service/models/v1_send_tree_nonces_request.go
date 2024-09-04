// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1SendTreeNoncesRequest v1 send tree nonces request
//
// swagger:model v1SendTreeNoncesRequest
type V1SendTreeNoncesRequest struct {

	// public key
	PublicKey string `json:"publicKey,omitempty"`

	// round Id
	RoundID string `json:"roundId,omitempty"`

	// tree nonces
	TreeNonces string `json:"treeNonces,omitempty"`
}

// Validate validates this v1 send tree nonces request
func (m *V1SendTreeNoncesRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this v1 send tree nonces request based on context it is used
func (m *V1SendTreeNoncesRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *V1SendTreeNoncesRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1SendTreeNoncesRequest) UnmarshalBinary(b []byte) error {
	var res V1SendTreeNoncesRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
