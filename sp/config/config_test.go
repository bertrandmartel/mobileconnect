package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	config := &Config{
		Version:           "0.1",
		Port:              6004,
		ServerPath:        "http://localhost",
		DiscoveryEndpoint: "https://discovery.sandbox.mobileconnect.io/v2/discovery",
		AuthOptions: AuthOptions{
			RedirectURI:         "http://localhost:6004/callback",
			Scope:               "openid mc_authz mc_identity_signup",
			Version:             "mc_di_r2_v2.3",
			AcrValues:           "3",
			ClientName:          "MCTesting",
			BindingMessage:      "some message",
			Context:             "Login",
			JwtVerificationSkip: []string{"nonce", "acr"},
		},
		Client: Client{
			ClientID:     "client_id_for_discoverty",
			ClientSecret: "client_secret_for_discoverty",
			RedirectURI:  []string{"http://localhost:6004/discovery_callback"},
		},
	}
	data, err := ParseConfig("../../test/config_test.json")
	assert.Nil(t, err)
	assert.NotNil(t, data)
	assert.Equal(t, config.Version, data.Version)
	assert.Equal(t, config.Port, data.Port)
	assert.Equal(t, config.ServerPath, data.ServerPath)
	assert.Equal(t, config.DiscoveryEndpoint, data.DiscoveryEndpoint)
	assert.Equal(t, config.AuthOptions.RedirectURI, data.AuthOptions.RedirectURI)
	assert.Equal(t, config.AuthOptions.Scope, data.AuthOptions.Scope)
	assert.Equal(t, config.AuthOptions.Version, data.AuthOptions.Version)
	assert.Equal(t, config.AuthOptions.AcrValues, data.AuthOptions.AcrValues)
	assert.Equal(t, config.AuthOptions.ClientName, data.AuthOptions.ClientName)
	assert.Equal(t, config.AuthOptions.BindingMessage, data.AuthOptions.BindingMessage)
	assert.Equal(t, config.AuthOptions.Context, data.AuthOptions.Context)
	assert.Equal(t, len(config.AuthOptions.JwtVerificationSkip), len(data.AuthOptions.JwtVerificationSkip))
	for i := range config.AuthOptions.JwtVerificationSkip {
		assert.Equal(t, config.AuthOptions.JwtVerificationSkip[i], data.AuthOptions.JwtVerificationSkip[i])
	}
	assert.Equal(t, config.Client.ClientID, data.Client.ClientID)
	assert.Equal(t, config.Client.ClientSecret, data.Client.ClientSecret)
	assert.Equal(t, len(config.Client.RedirectURI), len(data.Client.RedirectURI))
	for i := range config.Client.RedirectURI {
		assert.Equal(t, config.Client.RedirectURI[i], data.Client.RedirectURI[i])
	}
}

func TestFileNotFound(t *testing.T) {
	data, err := ParseConfig("../../test/config_test1.json")
	assert.Nil(t, data)
	assert.NotNil(t, err)
}
