package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type Config struct { //nolint:maligned
	LogLevel                   string `yaml:"log_level"`
	Listen                     string `yaml:"listen"`
	EnableServerTLS            bool   `yaml:"enable_server_tls"`
	Cert                       string `yaml:"cert"`
	Key                        string `yaml:"key"`
	CfAPI                      string `yaml:"cf_api"`
	PcapServerPort             string `yaml:"pcap_server_port"`
	PcapServerClientCert       string `yaml:"pcap_server_client_cert"`
	PcapServerClientKey        string `yaml:"pcap_server_client_key"`
	PcapServerCaCert           string `yaml:"pcap_server_ca_cert"`
	PcapServerName             string `yaml:"pcap_server_name"`
	PcapServerClientSkipVerify bool   `yaml:"pcap_server_client_skip_verify"`
	CLIDownloadRoot            string `yaml:"cli_download_root"`
}

var DefaultConfig = Config{
	LogLevel:                   "debug",
	Listen:                     ":8080",
	EnableServerTLS:            false,
	Cert:                       "test/server.crt",
	Key:                        "test/server.key",
	CfAPI:                      "https://api.cf.aws-cfn02.aws.cfi.sapcloud.io",
	PcapServerPort:             "9494",
	PcapServerClientCert:       "test/client.crt",
	PcapServerClientKey:        "test/client.key",
	PcapServerCaCert:           "test/cacert.pem",
	PcapServerName:             "",
	PcapServerClientSkipVerify: true,
	CLIDownloadRoot:            "cli/build",
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
	//TODO implement
	return nil
}
