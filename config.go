package main

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type Config struct {
	LogLevel       string `yaml:"log_level"`
	Listen         string `yaml:"listen"`
	ContainerStore string `yaml:"container_store"`
	RunC           string `yaml:"runc"`
	RunCRoot       string `yaml:"runc_root"`
	Cert           string `yaml:"cert"`
	Key            string `yaml:"key"`
	CaCert         string `yaml:"ca_cert"`
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

func (c *Config) NewServer() *server {
	server := &server{
		config: c,
	}
	return server
}
