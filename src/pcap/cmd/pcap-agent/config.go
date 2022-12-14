package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

var DefaultConfig = Config{
	Port: 8080,
}

type Config struct {
	// Port is the port the agent will listen on.
	Port int `yaml:"port"`
	Tls  *struct {
		// Certificate holds the path to the PEM encoded certificate (chain).
		Certificate string `yaml:"certificate"`
		// PrivateKey holds the path to the PEM encoded private key.
		PrivateKey string `yaml:"privateKey"`
		// CertificateAuthority holds the path to the PEM encoded CA bundle which is used
		// to request and verify client certificates.
		CertificateAuthority string `yaml:"certificateAuthority"`
	} `yaml:"tls,omitempty"`
}

func parseConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return DefaultConfig, fmt.Errorf("parse config: %w", err)
	}

	var c Config
	err = yaml.NewDecoder(f).Decode(&c)
	if err != nil {
		return DefaultConfig, fmt.Errorf("parse config: %w", err)
	}

	return c, nil
}
