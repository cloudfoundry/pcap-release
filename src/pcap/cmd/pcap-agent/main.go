// Package pcap-agent is the entry point for running the pcap-agent.
//
// Supported platforms are darwin and linux, either as arm64 or amd64 due to the os signals being used.
//go:build unix && (amd64 || arm64)

package main

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/cloudfoundry/pcap-release/src/pcap"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func main() {
	var err error

	defer func() {
		if err != nil {
			os.Exit(1)
		}
	}()

	log := zap.L()
	log.Info("init phase done, starting agent", zap.Int64("compatibilityLevel", pcap.CompatibilityLevel))

	var config Config
	switch len(os.Args) {
	case 1:
		config = DefaultConfig
	case 2: //nolint:gomnd // two arguments mean parse the config.
		config, err = parseConfig(os.Args[1])
	default:
		err = fmt.Errorf("invalid number of arguments, expected 1 or 2 but got %d", len(os.Args))
	}
	if err != nil {
		log.Error("unable to load config", zap.Error(err))
		return
	}

	err = config.validate()
	if err != nil {
		log.Error("unable to validate config", zap.Error(err))
		return
	}

	agent := pcap.NewAgent(config.Buffer, config.ID)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", config.Listen.Port))
	if err != nil {
		log.Error("unable to create listener", zap.Error(err))
		return
	}

	tlsCredentials, err := config.TLSCredentials()
	if err != nil {
		log.Error("unable to load provided TLS credentials", zap.Error(err))
		return
	}

	server := grpc.NewServer(grpc.Creds(tlsCredentials))
	pcap.RegisterAgentServer(server, agent)

	go pcap.StopOnSignal(log, agent, server, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	log.Info("starting server")
	err = server.Serve(lis)
	if err != nil {
		log.Error("serve returned unsuccessfully", zap.Error(err))
		return
	}

	log.Info("serve returned successfully")
}
