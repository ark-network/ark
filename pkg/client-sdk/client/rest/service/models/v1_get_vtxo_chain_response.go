// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// V1GetVtxoChainResponse v1 get vtxo chain response
//
// swagger:model v1GetVtxoChainResponse
type V1GetVtxoChainResponse struct {

	// graph
	Graph map[string]V1IndexerTransactions `json:"graph,omitempty"`

	// page
	Page *V1IndexerPageResponse `json:"page,omitempty"`
}

// Validate validates this v1 get vtxo chain response
func (m *V1GetVtxoChainResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateGraph(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePage(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1GetVtxoChainResponse) validateGraph(formats strfmt.Registry) error {
	if swag.IsZero(m.Graph) { // not required
		return nil
	}

	for k := range m.Graph {

		if err := validate.Required("graph"+"."+k, "body", m.Graph[k]); err != nil {
			return err
		}
		if val, ok := m.Graph[k]; ok {
			if err := val.Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("graph" + "." + k)
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("graph" + "." + k)
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1GetVtxoChainResponse) validatePage(formats strfmt.Registry) error {
	if swag.IsZero(m.Page) { // not required
		return nil
	}

	if m.Page != nil {
		if err := m.Page.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("page")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("page")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this v1 get vtxo chain response based on the context it is used
func (m *V1GetVtxoChainResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateGraph(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePage(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1GetVtxoChainResponse) contextValidateGraph(ctx context.Context, formats strfmt.Registry) error {

	for k := range m.Graph {

		if val, ok := m.Graph[k]; ok {
			if err := val.ContextValidate(ctx, formats); err != nil {
				return err
			}
		}

	}

	return nil
}

func (m *V1GetVtxoChainResponse) contextValidatePage(ctx context.Context, formats strfmt.Registry) error {

	if m.Page != nil {

		if swag.IsZero(m.Page) { // not required
			return nil
		}

		if err := m.Page.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("page")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("page")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *V1GetVtxoChainResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1GetVtxoChainResponse) UnmarshalBinary(b []byte) error {
	var res V1GetVtxoChainResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
