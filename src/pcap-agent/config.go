package main

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type Config struct {
	LogLevel        string `yaml:"log_level"`
	Listen          string `yaml:"listen"`
	EnableServerTLS bool   `yaml:"enable_tls"`
	ContainerStore  string `yaml:"container_store"`
	RunC            string `yaml:"runc"`
	RunCRoot        string `yaml:"runc_root"`
	Cert            string `yaml:"cert"`
	Key             string `yaml:"key"`
	CaCert          string `yaml:"ca_cert"`
}

var DefaultConfig = Config{
	LogLevel:        "debug",
	Listen:          ":9494",
	EnableServerTLS: false,
	ContainerStore:  "/var/vcap/data/container-metadata/store.json",
	RunC:            "/var/vcap/packages/runc/bin/runc",
	RunCRoot:        "/run/containerd/runc/garden",
	Cert:            "",
	Key:             "",
	CaCert:          "",
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
	return nil
}
