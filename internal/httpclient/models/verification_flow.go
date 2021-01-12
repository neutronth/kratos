// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// VerificationFlow VerificationFlow VerificationFlow VerificationFlow A Verification Flow
//
// Used to verify an out-of-band communication
// channel such as an email address or a phone number.
//
// For more information head over to: https://www.ory.sh/docs/kratos/selfservice/flows/verify-email-account-activation
//
// swagger:model verificationFlow
type VerificationFlow struct {

	// Active, if set, contains the registration method that is being used. It is initially
	// not set.
	Active string `json:"active,omitempty"`

	// ExpiresAt is the time (UTC) when the request expires. If the user still wishes to verify the address,
	// a new request has to be initiated.
	// Format: date-time
	// Format: date-time
	// Format: date-time
	// Format: date-time
	ExpiresAt strfmt.DateTime `json:"expires_at,omitempty"`

	// id
	// Format: uuid4
	ID UUID `json:"id,omitempty"`

	// IssuedAt is the time (UTC) when the request occurred.
	// Format: date-time
	// Format: date-time
	// Format: date-time
	// Format: date-time
	IssuedAt strfmt.DateTime `json:"issued_at,omitempty"`

	// messages
	Messages Messages `json:"messages,omitempty"`

	// Methods contains context for all account verification methods. If a registration request has been
	// processed, but for example the password is incorrect, this will contain error messages.
	// Required: true
	Methods map[string]VerificationFlowMethod `json:"methods"`

	// RequestURL is the initial URL that was requested from ORY Kratos. It can be used
	// to forward information contained in the URL's path or query for example.
	RequestURL string `json:"request_url,omitempty"`

	// state
	// Required: true
	State State `json:"state"`

	// type
	Type Type `json:"type,omitempty"`
}

// Validate validates this verification flow
func (m *VerificationFlow) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateExpiresAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIssuedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMessages(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMethods(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateState(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *VerificationFlow) validateExpiresAt(formats strfmt.Registry) error {

	if swag.IsZero(m.ExpiresAt) { // not required
		return nil
	}

	if err := validate.FormatOf("expires_at", "body", "date-time", m.ExpiresAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *VerificationFlow) validateID(formats strfmt.Registry) error {

	if swag.IsZero(m.ID) { // not required
		return nil
	}

	if err := m.ID.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("id")
		}
		return err
	}

	return nil
}

func (m *VerificationFlow) validateIssuedAt(formats strfmt.Registry) error {

	if swag.IsZero(m.IssuedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("issued_at", "body", "date-time", m.IssuedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *VerificationFlow) validateMessages(formats strfmt.Registry) error {

	if swag.IsZero(m.Messages) { // not required
		return nil
	}

	if err := m.Messages.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("messages")
		}
		return err
	}

	return nil
}

func (m *VerificationFlow) validateMethods(formats strfmt.Registry) error {

	for k := range m.Methods {

		if err := validate.Required("methods"+"."+k, "body", m.Methods[k]); err != nil {
			return err
		}
		if val, ok := m.Methods[k]; ok {
			if err := val.Validate(formats); err != nil {
				return err
			}
		}

	}

	return nil
}

func (m *VerificationFlow) validateState(formats strfmt.Registry) error {

	if err := m.State.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("state")
		}
		return err
	}

	return nil
}

func (m *VerificationFlow) validateType(formats strfmt.Registry) error {

	if swag.IsZero(m.Type) { // not required
		return nil
	}

	if err := m.Type.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("type")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *VerificationFlow) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *VerificationFlow) UnmarshalBinary(b []byte) error {
	var res VerificationFlow
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
