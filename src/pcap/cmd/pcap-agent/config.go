package main

import (
	"fmt"
	"os"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

var DefaultConfig = Config{
	Listen: pcap.Listen{Port: 8083},
	Buffer: pcap.BufferConf{
		Size:       100,
		UpperLimit: 95,
		LowerLimit: 60,
	},
	LogLevel: "debug",
}

type Config struct {
	// Port is the port the agent will listen on.
	Listen   pcap.Listen     `yaml:"listen"`
	Buffer   pcap.BufferConf `yaml:"buffer"`
	LogLevel string          `yaml:"logLevel"`
	ID       string          `yaml:"id" validate:"required"`
}

func (c Config) validate() error {
	return validator.New().Struct(c)
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
