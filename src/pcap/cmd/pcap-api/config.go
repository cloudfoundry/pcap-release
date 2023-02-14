package main

import (
	"fmt"
	"os"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

var DefaultAPIConfig = APIConfig{
	Listen: &pcap.Listen{Port: 8080},
	Buffer: pcap.BufferConf{
		Size:       100,
		UpperLimit: 95,
		LowerLimit: 60,
	},
	LogLevel: "debug",
	Agents: &pcap.AgentMTLS{
		DefaultPort: 9494,
		MTLS:        nil,
	},
	ManualEndpoints: pcap.ManualEndpoints{Targets: []pcap.AgentEndpoint{{IP: "localhost", Port: 8083, Identifier: "test-agent/1"}}},
}

type APIConfig struct {
	Listen             *pcap.Listen    `yaml:"listen"`
	ID                 string          `yaml:"id"`
	Agents             *pcap.AgentMTLS `yaml:"agents"`
	Buffer             pcap.BufferConf `yaml:"buffer"`
	LogLevel           string          `yaml:"log_level"`
	ConcurrentCaptures int             `yaml:"concurrent_captures"`

	// TODO: Add BOSH and CF specific config fragments
	ManualEndpoints pcap.ManualEndpoints
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
