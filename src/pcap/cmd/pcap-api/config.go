package main

import (
	"fmt"
	"os"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

var DefaultAPIConfig = APIConfig{
	Port:      8080,
	AgentPort: 9494,
	Buffer: pcap.BufferConf{
		Size:       100,
		UpperLimit: 95,
		LowerLimit: 60,
	},
	LogLevel:           "debug",
	AgentTLSSkipVerify: false,
	ManualEndpoints:    pcap.ManualEndpoints{Targets: []pcap.AgentEndpoint{{IP: "localhost", Port: 8083}}},
}

type APIConfig struct {
	AgentPort int `yaml:"agent_port" validate:"gt=0,lte=65535"`
	// TODO compare listen / api port with api/spec
	Port               int             `yaml:"listen"`
	ClientCert         string          `yaml:"client_certificate,omitempty" validate:"file"`
	ClientKey          string          `yaml:"client_key,omitempty" validate:"file"`
	TLS                *TLS            `yaml:"tls,omitempty"`
	Buffer             pcap.BufferConf `yaml:"buffer"`
	LogLevel           string          `yaml:"log_level"`
	AgentTLSSkipVerify bool            `yaml:"agent_tls_skip_verify" validate:"boolean"`
	AgentCommonName    string          `yaml:"agent_common_name,omitempty" validate:"required_if=AgentTLSSkipVerify false"`
	AgentCA            string          `yaml:"agent_ca,omitempty" validate:"required_if=AgentTLSSkipVerify false"`
	ManualEndpoints    pcap.ManualEndpoints
}

type TLS struct {
	// Certificate holds the path to the PEM encoded certificate (chain).
	Certificate string `yaml:"certificate" validate:"file"`
	// PrivateKey holds the path to the PEM encoded private key.
	PrivateKey string `yaml:"private_key" validate:"file"`
	// CertificateAuthority holds the path to the PEM encoded CA bundle which is used
	// to request and verify client certificates.
	CertificateAuthority string `yaml:"ca" validate:"file"`
}

func (c APIConfig) validate() error {
	return validator.New().Struct(c)
}

func parseAPIConfig(path string) (APIConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return DefaultAPIConfig, fmt.Errorf("parse config: %w", err)
	}

	var c APIConfig
	err = yaml.NewDecoder(f).Decode(&c)
	if err != nil {
		return DefaultAPIConfig, fmt.Errorf("parse config: %w", err)
	}

	return c, nil
}
