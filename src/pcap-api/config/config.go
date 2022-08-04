package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type Config struct { //nolint:maligned
	LogLevel           string `yaml:"log_level"`
	Listen             string `yaml:"listen"`
	EnableServerTLS    bool   `yaml:"enable_server_tls"`
	Cert               string `yaml:"cert"`
	Key                string `yaml:"key"`
	CfAPI              string `yaml:"cf_api"`
	AgentPort          string `yaml:"agent_port"`
	ClientCert         string `yaml:"client_cert"`
	ClientCertKey      string `yaml:"client_cert_key"`
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
	CfAPI:              "https://api.cf.aws-cfn02.aws.cfi.sapcloud.io",
	AgentPort:          "9494",
	ClientCert:         "test/client.crt",
	ClientCertKey:      "test/client.key",
	AgentCa:            "test/cacert.pem",
	AgentCommonName:    "",
	AgentTlsSkipVerify: true,
	CLIDownloadRoot:    "cli/build",
}

func NewConfigFromFile(filename string) (*Config, error) {
	data, err := ioutil.ReadFile(filename)
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
