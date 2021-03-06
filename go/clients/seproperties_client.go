package clients

// This file is auto-generated.
// Please contact avi-sdk@avinetworks.com for any change requests.

import (
	"github.com/avinetworks/sdk/go/models"
	"github.com/avinetworks/sdk/go/session"
)

// SePropertiesClient is a client for avi SeProperties resource
type SePropertiesClient struct {
	aviSession *session.AviSession
}

// NewSePropertiesClient creates a new client for SeProperties resource
func NewSePropertiesClient(aviSession *session.AviSession) *SePropertiesClient {
	return &SePropertiesClient{aviSession: aviSession}
}

func (client *SePropertiesClient) getAPIPath(uuid string) string {
	path := "api/seproperties"
	if uuid != "" {
		path += "/" + uuid
	}
	return path
}

// GetAll is a collection API to get a list of SeProperties objects
func (client *SePropertiesClient) GetAll() ([]*models.SeProperties, error) {
	var plist []*models.SeProperties
	err := client.aviSession.GetCollection(client.getAPIPath(""), &plist)
	return plist, err
}

// Get an existing SeProperties by uuid
func (client *SePropertiesClient) Get(uuid string) (*models.SeProperties, error) {
	var obj *models.SeProperties
	err := client.aviSession.Get(client.getAPIPath(uuid), &obj)
	return obj, err
}

// GetByName - Get an existing SeProperties by name
func (client *SePropertiesClient) GetByName(name string) (*models.SeProperties, error) {
	var obj *models.SeProperties
	err := client.aviSession.GetObjectByName("seproperties", name, &obj)
	return obj, err
}

// Create a new SeProperties object
func (client *SePropertiesClient) Create(obj *models.SeProperties) (*models.SeProperties, error) {
	var robj *models.SeProperties
	err := client.aviSession.Post(client.getAPIPath(""), obj, &robj)
	return robj, err
}

// Update an existing SeProperties object
func (client *SePropertiesClient) Update(obj *models.SeProperties) (*models.SeProperties, error) {
	var robj *models.SeProperties
	path := client.getAPIPath(obj.UUID)
	err := client.aviSession.Put(path, obj, &robj)
	return robj, err
}

// Delete an existing SeProperties object with a given UUID
func (client *SePropertiesClient) Delete(uuid string) error {
	return client.aviSession.Delete(client.getAPIPath(uuid))
}

// DeleteByName - Delete an existing SeProperties object with a given name
func (client *SePropertiesClient) DeleteByName(name string) error {
	res, err := client.GetByName(name)
	if err != nil {
		return err
	}
	return client.Delete(res.UUID)
}
