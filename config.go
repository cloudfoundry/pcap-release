package main

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type Config struct {
	LogLevel             string `yaml:"log_level"`
	Listen               string `yaml:"listen"`
	Cert                 string `yaml:"cert"`
	Key                  string `yaml:"key"`
	CfApi                string `yaml:"cf_api"`
	PcapServerPort       string `yaml:"pcap_server_port"`
	PcapServerClientCert string `yaml:"pcap_server_client_cert"`
	PcapServerClientKey  string `yaml:"pcap_server_client_key"`
	PcapServerCaCert     string `yaml:"pcap_server_ca_cert"`
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

func (c *Config) NewServer() *server {
	server := &server{
		config: c,
	}
	return server
}
