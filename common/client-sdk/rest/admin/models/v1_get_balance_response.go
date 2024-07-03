// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
)

// V1GetBalanceResponse v1 get balance response
// swagger:model v1GetBalanceResponse
type V1GetBalanceResponse struct {

	// connectors account
	ConnectorsAccount *V1Balance `json:"connectorsAccount,omitempty"`

	// main account
	MainAccount *V1Balance `json:"mainAccount,omitempty"`
}

// Validate validates this v1 get balance response
func (m *V1GetBalanceResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateConnectorsAccount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMainAccount(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1GetBalanceResponse) validateConnectorsAccount(formats strfmt.Registry) error {

	if swag.IsZero(m.ConnectorsAccount) { // not required
		return nil
	}

	if m.ConnectorsAccount != nil {
		if err := m.ConnectorsAccount.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("connectorsAccount")
			}
			return err
		}
	}

	return nil
}

func (m *V1GetBalanceResponse) validateMainAccount(formats strfmt.Registry) error {

	if swag.IsZero(m.MainAccount) { // not required
		return nil
	}

	if m.MainAccount != nil {
		if err := m.MainAccount.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("mainAccount")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *V1GetBalanceResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1GetBalanceResponse) UnmarshalBinary(b []byte) error {
	var res V1GetBalanceResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
