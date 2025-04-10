// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1GetInfoResponse v1 get info response
//
// swagger:model v1GetInfoResponse
type V1GetInfoResponse struct {

	// boarding descriptor template
	BoardingDescriptorTemplate string `json:"boardingDescriptorTemplate,omitempty"`

	// dust
	Dust string `json:"dust,omitempty"`

	// forfeit address
	ForfeitAddress string `json:"forfeitAddress,omitempty"`

	// market hour
	MarketHour *V1MarketHour `json:"marketHour,omitempty"`

	// network
	Network string `json:"network,omitempty"`

	// pubkey
	Pubkey string `json:"pubkey,omitempty"`

	// round interval
	RoundInterval string `json:"roundInterval,omitempty"`

	// unilateral exit delay
	UnilateralExitDelay string `json:"unilateralExitDelay,omitempty"`

	// -1 means no limit (default), 0 means boarding not allowed
	UtxoMaxAmount string `json:"utxoMaxAmount,omitempty"`

	// -1 means native dust limit (default)
	UtxoMinAmount string `json:"utxoMinAmount,omitempty"`

	// version
	Version string `json:"version,omitempty"`

	// vtxo descriptor templates
	VtxoDescriptorTemplates []string `json:"vtxoDescriptorTemplates"`

	// -1 means no limit (default)
	VtxoMaxAmount string `json:"vtxoMaxAmount,omitempty"`

	// -1 means native dust limit (default)
	VtxoMinAmount string `json:"vtxoMinAmount,omitempty"`

	// vtxo tree expiry
	VtxoTreeExpiry string `json:"vtxoTreeExpiry,omitempty"`
}

// Validate validates this v1 get info response
func (m *V1GetInfoResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateMarketHour(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1GetInfoResponse) validateMarketHour(formats strfmt.Registry) error {
	if swag.IsZero(m.MarketHour) { // not required
		return nil
	}

	if m.MarketHour != nil {
		if err := m.MarketHour.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("marketHour")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("marketHour")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this v1 get info response based on the context it is used
func (m *V1GetInfoResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateMarketHour(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1GetInfoResponse) contextValidateMarketHour(ctx context.Context, formats strfmt.Registry) error {

	if m.MarketHour != nil {

		if swag.IsZero(m.MarketHour) { // not required
			return nil
		}

		if err := m.MarketHour.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("marketHour")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("marketHour")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *V1GetInfoResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1GetInfoResponse) UnmarshalBinary(b []byte) error {
	var res V1GetInfoResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
