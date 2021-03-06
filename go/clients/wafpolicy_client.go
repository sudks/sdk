package clients

// This file is auto-generated.
// Please contact avi-sdk@avinetworks.com for any change requests.

import (
	"github.com/avinetworks/sdk/go/models"
	"github.com/avinetworks/sdk/go/session"
)

// WafPolicyClient is a client for avi WafPolicy resource
type WafPolicyClient struct {
	aviSession *session.AviSession
}

// NewWafPolicyClient creates a new client for WafPolicy resource
func NewWafPolicyClient(aviSession *session.AviSession) *WafPolicyClient {
	return &WafPolicyClient{aviSession: aviSession}
}

func (client *WafPolicyClient) getAPIPath(uuid string) string {
	path := "api/wafpolicy"
	if uuid != "" {
		path += "/" + uuid
	}
	return path
}

// GetAll is a collection API to get a list of WafPolicy objects
func (client *WafPolicyClient) GetAll() ([]*models.WafPolicy, error) {
	var plist []*models.WafPolicy
	err := client.aviSession.GetCollection(client.getAPIPath(""), &plist)
	return plist, err
}

// Get an existing WafPolicy by uuid
func (client *WafPolicyClient) Get(uuid string) (*models.WafPolicy, error) {
	var obj *models.WafPolicy
	err := client.aviSession.Get(client.getAPIPath(uuid), &obj)
	return obj, err
}

// GetByName - Get an existing WafPolicy by name
func (client *WafPolicyClient) GetByName(name string) (*models.WafPolicy, error) {
	var obj *models.WafPolicy
	err := client.aviSession.GetObjectByName("wafpolicy", name, &obj)
	return obj, err
}

// Create a new WafPolicy object
func (client *WafPolicyClient) Create(obj *models.WafPolicy) (*models.WafPolicy, error) {
	var robj *models.WafPolicy
	err := client.aviSession.Post(client.getAPIPath(""), obj, &robj)
	return robj, err
}

// Update an existing WafPolicy object
func (client *WafPolicyClient) Update(obj *models.WafPolicy) (*models.WafPolicy, error) {
	var robj *models.WafPolicy
	path := client.getAPIPath(obj.UUID)
	err := client.aviSession.Put(path, obj, &robj)
	return robj, err
}

// Delete an existing WafPolicy object with a given UUID
func (client *WafPolicyClient) Delete(uuid string) error {
	return client.aviSession.Delete(client.getAPIPath(uuid))
}

// DeleteByName - Delete an existing WafPolicy object with a given name
func (client *WafPolicyClient) DeleteByName(name string) error {
	res, err := client.GetByName(name)
	if err != nil {
		return err
	}
	return client.Delete(res.UUID)
}
