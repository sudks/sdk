package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
)

// GeoLocation geo location
// swagger:model GeoLocation
type GeoLocation struct {

	// Latitude of the location. Field introduced in 17.1.1.
	Latitude float32 `json:"latitude,omitempty"`

	// Longitude of the location. Field introduced in 17.1.1.
	Longitude float32 `json:"longitude,omitempty"`

	// Location name in the format Country/State/City. Field introduced in 17.1.1.
	Name string `json:"name,omitempty"`

	// Location tag string - example  USEast. Field introduced in 17.1.1.
	Tag string `json:"tag,omitempty"`
}

// Validate validates this geo location
func (m *GeoLocation) Validate(formats strfmt.Registry) error {
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}