package main

import (
	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/cloudfoundry/pcap-release/src/pcap/cmd"

	"github.com/go-playground/validator/v10"
)

var DefaultConfig = Config{cmd.CommonConfig{
	Listen: pcap.Listen{Port: 8083}, //nolint:gomnd // default value used for testing
	Buffer: pcap.BufferConf{
		Size:       100, //nolint:gomnd // default value used for testing
		UpperLimit: 95,  //nolint:gomnd // default value used for testing
		LowerLimit: 60,  //nolint:gomnd // default value used for testing
	},
	LogLevel: "debug",
	ID:       "test-agent",
}}

type Config struct {
	// Port is the port the agent will listen on.
	cmd.CommonConfig
}

/*func NewConfig(genericConfig cmd.CommonConfig) *Config {
	return &Config{CommonConfig: genericConfig}
}*/

func (c Config) validate() error {
	return validator.New().Struct(c)
}
