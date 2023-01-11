package main

import (
	"fmt"
	"os"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"

	"github.com/cloudfoundry/pcap-release/src/pcap"
)

var DefaultApiConfig = ApiConfig{
	Port: 8080,
	Buffer: pcap.BufferConf{
		Size:       100,
		UpperLimit: 95,
		LowerLimit: 60,
	},
	LogLevel: "debug",
}

type ApiConfig struct {
	// Port is the port the agent will listen on.
	Port int `yaml:"port" validate:"gt=0,lte=65535"`
	Tls  *struct {
		// Certificate holds the path to the PEM encoded certificate (chain).
		Certificate string `yaml:"certificate" validate:"file"`
		// PrivateKey holds the path to the PEM encoded private key.
		PrivateKey string `yaml:"privateKey" validate:"file"`
		// CertificateAuthority holds the path to the PEM encoded CA bundle which is used
		// to request and verify client certificates.
		CertificateAuthority string `yaml:"certificateAuthority" validate:"file"`
	} `yaml:"tls,omitempty"`
	Buffer   pcap.BufferConf `yaml:"buffer"`
	LogLevel string          `yaml:"logLevel"`
}

func (c ApiConfig) validate() error {
	return validator.New().Struct(c)
}

func parseApiConfig(path string) (ApiConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return DefaultApiConfig, fmt.Errorf("parse config: %w", err)
	}

	var c ApiConfig
	err = yaml.NewDecoder(f).Decode(&c)
	if err != nil {
		return DefaultApiConfig, fmt.Errorf("parse config: %w", err)
	}

	return c, nil
}
