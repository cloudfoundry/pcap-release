package main

import (
	"fmt"
	"os"
	"time"

	"github.com/cloudfoundry/pcap-release/src/pcap"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

var DefaultAPIConfig = APIConfig{
	NodeConfig: pcap.NodeConfig{
		Listen: pcap.Listen{Port: 8080}, //nolint:mnd // default port
		Buffer: pcap.BufferConf{
			Size:       100, //nolint:mnd // default size
			UpperLimit: 95,  //nolint:mnd // default size
			LowerLimit: 60,  //nolint:mnd // default size
		},
		LogLevel: "debug",
		ID:       "test-api",
	},
	AgentsMTLS:         nil,
	DrainTimeout:       10 * time.Second, //nolint:mnd // default configuration
	ConcurrentCaptures: 5,                //nolint:mnd // default configuration
}

type APIConfig struct {
	pcap.NodeConfig    `yaml:"-,inline"`
	AgentsMTLS         *pcap.ClientTLS `yaml:"agents_mtls" validate:"omitempty"`
	ConcurrentCaptures int32           `yaml:"concurrent_captures"`
	DrainTimeout       time.Duration   `yaml:"drain_timeout"`

	BoshResolverConfig *pcap.BoshResolverConfig `yaml:"bosh,omitempty" validate:"dive"`
	// TODO: Add CF specific config fragments
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
