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

func main() {
	log := zap.L()
	log.Info("init phase done, starting api")

	var err error
	var config = DefaultAPIConfig
	switch len(os.Args) {
	case 1:
		config = DefaultAPIConfig
	case 2: //nolint:gomnd // two arguments mean parse the config.
		config, err = parseAPIConfig(os.Args[1])
	default:
		err = fmt.Errorf("invalid number of arguments, expected 1 or 2 but got %d", len(os.Args))
	}

	if err != nil {
		log.Panic("Unable to initialize", zap.Error(err))
	}

	err = config.validate()
	if err != nil {
		log.Panic("Failed to validate config", zap.Error(err))
	}

	cmd.SetLogLevel(log, config.LogLevel)

	api, err := pcap.NewAPI(config.Buffer, *config.Agents, config.ID, config.ConcurrentCaptures)
	if err != nil {
		log.Panic("Unable to create api", zap.Error(err))
	}

	// set up a BoshResolver for each bosh environment
	registerBoshResolvers(config.BoshResolverConfigs, log, api)

	//TODO: CFAgentResolver

	if len(api.RegisteredResolverNames()) == 0 {
		log.Panic("Could not register any AgentResolvers")
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", config.Listen.Port))
	if err != nil {
		log.Panic("unable to create listener", zap.Error(err))
	}

	tlsCredentials, err := cmd.LoadTLSCredentials(config.CommonConfig)
	if err != nil {
		log.Panic("unable to load provided TLS credentials", zap.Error(err))
	}
	server := grpc.NewServer(grpc.Creds(tlsCredentials))
	pcap.RegisterAPIServer(server, api)

	go cmd.WaitForSignal(log, api, server)

	log.Info("starting server")
	err = server.Serve(lis)
	if err != nil {
		log.Panic("serve returned unsuccessfully", zap.Error(err))
	}

	log.Info("serve returned successfully")
}

// registerBoshResolvers tries to register all BoshResolvers defined in configs and registers them in api.
//
// Logs an error if the resolver could not be initialized.
func registerBoshResolvers(configs []pcap.BoshResolverConfig, log *zap.Logger, api *pcap.API) {
	for _, env := range configs {
		resolver, err := pcap.NewBoshResolver(env)
		if err != nil {
			log.Error("Failed to setup BoshResolver", zap.String(pcap.LogKeyResolver, env.EnvironmentAlias), zap.Error(err))
		}
		api.RegisterResolver(resolver)
	}
}
