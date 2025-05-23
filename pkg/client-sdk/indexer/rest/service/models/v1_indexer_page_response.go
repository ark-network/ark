// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1IndexerPageResponse v1 indexer page response
//
// swagger:model v1IndexerPageResponse
type V1IndexerPageResponse struct {

	// current
	Current int32 `json:"current,omitempty"`

	// next
	Next int32 `json:"next,omitempty"`

	// total
	Total int32 `json:"total,omitempty"`
}

// Validate validates this v1 indexer page response
func (m *V1IndexerPageResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this v1 indexer page response based on context it is used
func (m *V1IndexerPageResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *V1IndexerPageResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1IndexerPageResponse) UnmarshalBinary(b []byte) error {
	var res V1IndexerPageResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
