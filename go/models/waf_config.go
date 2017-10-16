package models

// This file is auto-generated.
// Please contact avi-sdk@avinetworks.com for any change requests.

// WafConfig waf config
// swagger:model WafConfig
type WafConfig struct {

	// WAF allowed HTTP Versions. Enum options - ZERO_NINE, ONE_ZERO, ONE_ONE. Field introduced in 17.2.1.
	AllowedHTTPVersions []string `json:"allowed_http_versions,omitempty"`

	// WAF allowed HTTP methods. Enum options - HTTP_METHOD_GET, HTTP_METHOD_HEAD, HTTP_METHOD_PUT, HTTP_METHOD_DELETE, HTTP_METHOD_POST, HTTP_METHOD_OPTIONS, HTTP_METHOD_TRACE. Field introduced in 17.2.1.
	AllowedMethods []string `json:"allowed_methods,omitempty"`

	// WAF allowed Content Types. Field introduced in 17.2.1.
	AllowedRequestContentTypes []string `json:"allowed_request_content_types,omitempty"`

	// Argument seperator. Field introduced in 17.2.1.
	ArgumentSeparator string `json:"argument_separator,omitempty"`

	// Maximum size for the client request body for file uploads. Allowed values are 1-32768. Field introduced in 17.2.1.
	ClientFileUploadMaxBodySize int32 `json:"client_file_upload_max_body_size,omitempty"`

	// Maximum size for the client request body for non-file uploads. Allowed values are 1-32768. Field introduced in 17.2.1.
	ClientNonfileUploadMaxBodySize int32 `json:"client_nonfile_upload_max_body_size,omitempty"`

	// 0  For Netscape Cookies. 1  For version 1 cookies. Allowed values are 0-1. Field introduced in 17.2.1.
	CookieFormatVersion int32 `json:"cookie_format_version,omitempty"`

	// WAF default action for Request Body Phase. Field introduced in 17.2.1.
	// Required: true
	RequestBodyDefaultAction string `json:"request_body_default_action"`

	// WAF default action for Request Header Phase. Field introduced in 17.2.1.
	// Required: true
	RequestHdrDefaultAction string `json:"request_hdr_default_action"`

	// WAF default action for Response Body Phase. Field introduced in 17.2.1.
	// Required: true
	ResponseBodyDefaultAction string `json:"response_body_default_action"`

	// WAF default action for Response Header Phase. Field introduced in 17.2.1.
	// Required: true
	ResponseHdrDefaultAction string `json:"response_hdr_default_action"`

	// WAF Restricted File Extensions. Field introduced in 17.2.1.
	RestrictedExtensions []string `json:"restricted_extensions,omitempty"`

	// WAF Restricted HTTP Headers. Field introduced in 17.2.1.
	RestrictedHeaders []string `json:"restricted_headers,omitempty"`

	// Maximum size for the backend response body. Allowed values are 1-32768. Field introduced in 17.2.1.
	ServerResponseMaxBodySize int32 `json:"server_response_max_body_size,omitempty"`
}
