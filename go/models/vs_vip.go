package models

// This file is auto-generated.
// Please contact avi-sdk@avinetworks.com for any change requests.

// VsVip vs vip
// swagger:model VsVip
type VsVip struct {

	//  It is a reference to an object of type Cloud. Field introduced in 17.1.1.
	// Read Only: true
	CloudRef string `json:"cloud_ref,omitempty"`

	// Service discovery specific data including fully qualified domain name, type and Time-To-Live of the DNS record. Field introduced in 17.1.1.
	DNSInfo []*DNSInfo `json:"dns_info,omitempty"`

	// Force placement on all Service Engines in the Service Engine Group (Container clouds only). Field introduced in 17.1.1.
	EastWestPlacement bool `json:"east_west_placement,omitempty"`

	// Name for the VsVip object. Field introduced in 17.1.1.
	// Required: true
	Name string `json:"name"`

	//  It is a reference to an object of type Tenant. Field introduced in 17.1.1.
	TenantRef string `json:"tenant_ref,omitempty"`

	// url
	// Read Only: true
	URL string `json:"url,omitempty"`

	// UUID of the VsVip object. Field introduced in 17.1.1.
	UUID string `json:"uuid,omitempty"`

	// List of Virtual Service IPs and other shareable entities. Field introduced in 17.1.1.
	Vip []*Vip `json:"vip,omitempty"`

	// Virtual Routing Context that the Virtual Service is bound to. This is used to provide the isolation of the set of networks the application is attached to. It is a reference to an object of type VrfContext. Field introduced in 17.1.1.
	VrfContextRef string `json:"vrf_context_ref,omitempty"`
}
