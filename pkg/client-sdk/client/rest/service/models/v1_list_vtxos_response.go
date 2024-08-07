// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1ListVtxosResponse v1 list vtxos response
//
// swagger:model v1ListVtxosResponse
type V1ListVtxosResponse struct {

	// spendable vtxos
	SpendableVtxos []*V1Vtxo `json:"spendableVtxos"`

	// spent vtxos
	SpentVtxos []*V1Vtxo `json:"spentVtxos"`
}

// Validate validates this v1 list vtxos response
func (m *V1ListVtxosResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSpendableVtxos(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSpentVtxos(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1ListVtxosResponse) validateSpendableVtxos(formats strfmt.Registry) error {
	if swag.IsZero(m.SpendableVtxos) { // not required
		return nil
	}

	for i := 0; i < len(m.SpendableVtxos); i++ {
		if swag.IsZero(m.SpendableVtxos[i]) { // not required
			continue
		}

		if m.SpendableVtxos[i] != nil {
			if err := m.SpendableVtxos[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("spendableVtxos" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("spendableVtxos" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1ListVtxosResponse) validateSpentVtxos(formats strfmt.Registry) error {
	if swag.IsZero(m.SpentVtxos) { // not required
		return nil
	}

	for i := 0; i < len(m.SpentVtxos); i++ {
		if swag.IsZero(m.SpentVtxos[i]) { // not required
			continue
		}

		if m.SpentVtxos[i] != nil {
			if err := m.SpentVtxos[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("spentVtxos" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("spentVtxos" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this v1 list vtxos response based on the context it is used
func (m *V1ListVtxosResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateSpendableVtxos(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSpentVtxos(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1ListVtxosResponse) contextValidateSpendableVtxos(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.SpendableVtxos); i++ {

		if m.SpendableVtxos[i] != nil {

			if swag.IsZero(m.SpendableVtxos[i]) { // not required
				return nil
			}

			if err := m.SpendableVtxos[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("spendableVtxos" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("spendableVtxos" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1ListVtxosResponse) contextValidateSpentVtxos(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.SpentVtxos); i++ {

		if m.SpentVtxos[i] != nil {

			if swag.IsZero(m.SpentVtxos[i]) { // not required
				return nil
			}

			if err := m.SpentVtxos[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("spentVtxos" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("spentVtxos" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *V1ListVtxosResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1ListVtxosResponse) UnmarshalBinary(b []byte) error {
	var res V1ListVtxosResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
