package clients

// This file is auto-generated.
// Please contact avi-sdk@avinetworks.com for any change requests.

import (
	"github.com/avinetworks/sdk/go/models"
	"github.com/avinetworks/sdk/go/session"
)

// DNSPolicyClient is a client for avi DNSPolicy resource
type DNSPolicyClient struct {
	aviSession *session.AviSession
}

// NewDNSPolicyClient creates a new client for DNSPolicy resource
func NewDNSPolicyClient(aviSession *session.AviSession) *DNSPolicyClient {
	return &DNSPolicyClient{aviSession: aviSession}
}

func (client *DNSPolicyClient) getAPIPath(uuid string) string {
	path := "api/dnspolicy"
	if uuid != "" {
		path += "/" + uuid
	}
	return path
}

// GetAll is a collection API to get a list of DNSPolicy objects
func (client *DNSPolicyClient) GetAll() ([]*models.DNSPolicy, error) {
	var plist []*models.DNSPolicy
	err := client.aviSession.GetCollection(client.getAPIPath(""), &plist)
	return plist, err
}

// Get an existing DNSPolicy by uuid
func (client *DNSPolicyClient) Get(uuid string) (*models.DNSPolicy, error) {
	var obj *models.DNSPolicy
	err := client.aviSession.Get(client.getAPIPath(uuid), &obj)
	return obj, err
}

// GetByName - Get an existing DNSPolicy by name
func (client *DNSPolicyClient) GetByName(name string) (*models.DNSPolicy, error) {
	var obj *models.DNSPolicy
	err := client.aviSession.GetObjectByName("dnspolicy", name, &obj)
	return obj, err
}

// Create a new DNSPolicy object
func (client *DNSPolicyClient) Create(obj *models.DNSPolicy) (*models.DNSPolicy, error) {
	var robj *models.DNSPolicy
	err := client.aviSession.Post(client.getAPIPath(""), obj, &robj)
	return robj, err
}

// Update an existing DNSPolicy object
func (client *DNSPolicyClient) Update(obj *models.DNSPolicy) (*models.DNSPolicy, error) {
	var robj *models.DNSPolicy
	path := client.getAPIPath(obj.UUID)
	err := client.aviSession.Put(path, obj, &robj)
	return robj, err
}

// Delete an existing DNSPolicy object with a given UUID
func (client *DNSPolicyClient) Delete(uuid string) error {
	return client.aviSession.Delete(client.getAPIPath(uuid))
}

// DeleteByName - Delete an existing DNSPolicy object with a given name
func (client *DNSPolicyClient) DeleteByName(name string) error {
	res, err := client.GetByName(name)
	if err != nil {
		return err
	}
	return client.Delete(res.UUID)
}
