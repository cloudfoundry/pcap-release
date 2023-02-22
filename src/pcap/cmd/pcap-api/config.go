package main

import (
	"fmt"
	"github.com/cloudfoundry/pcap-release/src/pcap/bosh"
	"os"
	"time"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/cloudfoundry/pcap-release/src/pcap/cmd"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

var DefaultAPIConfig = APIConfig{
	CommonConfig: cmd.CommonConfig{
		Listen: pcap.Listen{Port: 8080}, //nolint:gomnd // default port
		Buffer: pcap.BufferConf{
			Size:       100, //nolint:gomnd // default size
			UpperLimit: 95,  //nolint:gomnd // default size
			LowerLimit: 60,  //nolint:gomnd // default size
		},
		LogLevel: "debug",
		ID:       "test-api",
	},
	Agents: &pcap.AgentMTLS{
		MTLS: nil,
	},
	DrainTimeout:       10 * time.Second,
	ConcurrentCaptures: 5,
	//ManualEndpoints:    pcap.ManualEndpoints{Targets: []pcap.AgentEndpoint{{IP: "localhost", Port: 8083, Identifier: "test-agent/1"}}},
}

type APIConfig struct {
	cmd.CommonConfig
	Agents             *pcap.AgentMTLS `yaml:"agents"`
	ConcurrentCaptures int             `yaml:"concurrent_captures"`
	DrainTimeout       time.Duration   `yaml:"drain_timeout"`

	BoshEnvironments []bosh.Environment `yaml:"bosh_environments"`
	// TODO: Add BOSH and CF specific config fragments
	//ManualEndpoints pcap.ManualEndpoints
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
