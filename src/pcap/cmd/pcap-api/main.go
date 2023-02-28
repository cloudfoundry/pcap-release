// Package pcap-api is the entry point for running the pcap-api.
//
// Supported platforms are darwin and linux, either as arm64 or amd64 due to the os signals being used.
//go:build unix && (amd64 || arm64)

package main

import (
	"fmt"
	"net"
	"os"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/cloudfoundry/pcap-release/src/pcap/cmd"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

var zapConfig zap.Config

func main() {
	log := zap.L()
	log.Info("init phase done, starting api")

	var err error
	var config = DefaultAPIConfig
	switch len(os.Args) {
	case 1:
		config = DefaultAPIConfig
	case 2:
		config, err = parseAPIConfig(os.Args[1])
	default:
		err = fmt.Errorf("invalid number of arguments, expected 1 or 2 but got %d", len(os.Args))
	}

	if err != nil {
		log.Fatal("unable to initialize", zap.Error(err))
	}

	err = config.validate()
	if err != nil {
		log.Fatal("unable to validate config", zap.Error(err))
	}

	cmd.SetLogLevel(log, config.LogLevel)

	api, err := pcap.NewAPI(config.Buffer, *config.Agents, config.ID, config.ConcurrentCaptures)
	if err != nil {
		log.Fatal("unable to create api", zap.Error(err))
	}

	api.RegisterResolver(&pcap.BoshHandler{Config: config.ManualEndpoints})

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", config.Listen.Port))
	if err != nil {
		log.Fatal("unable to create listener", zap.Error(err))
	}

	tlsCredentials, err := cmd.LoadTLSCredentials(config.CommonConfig)
	if err != nil {
		log.Fatal("unable to load provided TLS credentials", zap.Error(err))
	}
	server := grpc.NewServer(grpc.Creds(tlsCredentials))
	pcap.RegisterAPIServer(server, api)

	go cmd.WaitForSignal(log, api, server)

	log.Info("starting server")
	err = server.Serve(lis)
	if err != nil {
		log.Fatal("serve returned unsuccessfully", zap.Error(err))
	}

	log.Info("serve returned successfully")
}
