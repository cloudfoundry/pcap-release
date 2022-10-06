package main

import (
	"os"

	"gopkg.in/yaml.v2"
)

// TODO: Consider splitting this into pcap-api, cf and bosh parts. cf and bosh could then be
// used to _not_ enable a specific capture endpoint when there's no configuration for it.
type Config struct { //nolint:maligned
	LogLevel           string `yaml:"log_level"`
	Listen             string `yaml:"listen"`
	EnableServerTLS    bool   `yaml:"enable_server_tls"`
	Cert               string `yaml:"cert"`
	Key                string `yaml:"key"`
	CfAPI              string `yaml:"cf_api"`
	BoshDirectorAPI    string `yaml:"bosh_director_api"`
	AgentPort          string `yaml:"agent_port"`
	ClientCert         string `yaml:"client_cert"`
	ClientCertKey      string `yaml:"client_key"`
	AgentCa            string `yaml:"agent_ca"`
	AgentCommonName    string `yaml:"agent_common_name"`
	AgentTlsSkipVerify bool   `yaml:"agent_tls_skip_verify"`
	CLIDownloadRoot    string `yaml:"cli_download_root"`
}

var DefaultConfig = Config{
	LogLevel:           "debug",
	Listen:             ":8080",
	EnableServerTLS:    false,
	Cert:               "test/server.crt",
	Key:                "test/server.key",
	CfAPI:              "",
	BoshDirectorAPI:    "",
	AgentPort:          "9494",
	ClientCert:         "test/client.crt",
	ClientCertKey:      "test/client.key",
	AgentCa:            "test/cacert.pem",
	AgentCommonName:    "",
	AgentTlsSkipVerify: true,
	CLIDownloadRoot:    "cli/build",
}

func NewConfigFromFile(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var config *Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	err = config.validate()
	if err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Config) validate() error {
	// TODO implement
	return nil
}
