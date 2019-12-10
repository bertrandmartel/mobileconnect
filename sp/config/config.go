package config

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

type Client struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURI  []string `json:"redirect_uri"`
}

type AuthOptions struct {
	RedirectURI         string   `json:"redirectUri"`
	Scope               string   `json:"scope"`
	Version             string   `json:"version"`
	AcrValues           string   `json:"acr_values"`
	ClientName          string   `json:"client_name"`
	BindingMessage      string   `json:"binding_message"`
	Context             string   `json:"context"`
	JwtVerificationSkip []string `json:"jwtFieldsToSkip"`
}

type Config struct {
	Version           string      `json:"version"`
	Port              int         `json:"port"`
	ServerPath        string      `json:"serverPath"`
	AuthOptions       AuthOptions `json:"authOptions"`
	DiscoveryEndpoint string      `json:"discoveryEndpoint"`
	Client            Client      `json:"client"`
}

func ParseConfig(path string) (config *Config, err error) {
	jsonFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var ret Config
	json.Unmarshal(byteValue, &ret)
	return &ret, nil
}
