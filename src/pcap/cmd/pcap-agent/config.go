package main

import (
	"fmt"
	"os"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"

	"github.com/cloudfoundry/pcap-release/src/pcap"
)

var DefaultConfig = Config{
	pcap.NodeConfig{
		Listen: pcap.Listen{Port: 8083}, //nolint:gomnd // default value used for testing
		Buffer: pcap.BufferConf{
			Size:       100, //nolint:gomnd // default value used for testing
			UpperLimit: 95,  //nolint:gomnd // default value used for testing
			LowerLimit: 60,  //nolint:gomnd // default value used for testing
		},
		LogLevel: "debug",
		ID:       "test-agent",
	},
}

type Config struct {
	pcap.NodeConfig `yaml:"-,inline"`
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
