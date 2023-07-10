package main

import (
	"testing"
	"time"

	"github.com/cloudfoundry/pcap-release/src/pcap"

	"github.com/google/go-cmp/cmp"
)

func TestAPIConfig(t *testing.T) {
	cfg, err := parseAPIConfig("../../config/api.example.yml")

	if err != nil {
		t.Errorf("Could not parse file: %v", err)
		return
	}

	// Adapt the pcap/config/agent.example.yml file when changing the structure or values.
	reference := APIConfig{
		NodeConfig: pcap.NodeConfig{
			Listen: pcap.Listen{
				Port: 8080,
				TLS: &pcap.ServerTLS{
					Certificate: "api-cert.pem",
					PrivateKey:  "api-cert.key",
					ClientCas:   "pcap-ca.pem",
				},
			},
			Buffer: pcap.BufferConf{
				Size:       100,
				UpperLimit: 95,
				LowerLimit: 90,
			},
			LogLevel: "debug",
			ID:       "pcap-api/234",
		},
		AgentsMTLS: &pcap.ClientTLS{
			Certificate: "api-client-cert.pem",
			PrivateKey:  "api-client-cert.key",
			RootCas:     "pcap-ca.pem",
			SkipVerify:  false,
			ServerName:  "pcap-agent.service.cf.internal",
		},
		ConcurrentCaptures: 5,
		DrainTimeout:       time.Second * 10,
		BoshResolverConfig: &pcap.BoshResolverConfig{
			RawDirectorURL: "https://bosh.service.cf.internal:8080",
			AgentPort:      9494,
			TokenScope:     "bosh.admin",
			TLS: &pcap.ClientTLS{
				RootCas:    "bosh-ca.pem",
				SkipVerify: false,
				ServerName: "bosh.service.cf.internal",
			},
		},
	}

	if !cmp.Equal(cfg, reference) {
		t.Errorf("Incorrectly parsed config. Diff: %s", cmp.Diff(cfg, reference))
	}
}
