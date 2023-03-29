package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/cloudfoundry/pcap-release/src/pcap"
)

func TestConfig(t *testing.T) {
	cfg, err := parseConfig("../../config/agent.example.yml")

	if err != nil {
		t.Errorf("Could not parse file: %v", err)
		return
	}

	// Adapt the pcap/config/agent.example.yml file when changing the structure or values.
	reference := Config{
		NodeConfig: pcap.NodeConfig{
			Listen: pcap.Listen{
				Port: 9494,
				TLS: &pcap.TLS{
					Certificate:          "agent-cert.pem",
					PrivateKey:           "agent-cert.key",
					CertificateAuthority: "pcap-ca.pem",
				},
			},
			Buffer: pcap.BufferConf{
				Size:       100,
				UpperLimit: 95,
				LowerLimit: 90,
			},
			LogLevel: "debug",
			ID:       "pcap-agent/123",
		},
	}

	if !cmp.Equal(cfg, reference) {
		t.Errorf("Incorrectly parsed config. Diff: %s", cmp.Diff(cfg, reference))
	}
}
