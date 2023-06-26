// Package pcap-api is the entry point for running the pcap-api.
//
// Supported platforms are darwin and linux, either as arm64 or amd64 due to the os signals being used.
//go:build unix && (amd64 || arm64)

package main

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"google.golang.org/grpc/credentials"

	"github.com/cloudfoundry/pcap-release/src/pcap"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func main() {
	log := zap.L()
	log.Info("init phase done, starting api")

	var err error

	defer func() {
		if err != nil {
			os.Exit(1)
		}
	}()

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
		log.Error("Unable to initialize", zap.Error(err))
		return
	}

	err = config.validate()
	if err != nil {
		log.Error("Failed to validate config", zap.Error(err))
		return
	}

	pcap.SetLogLevel(log, config.LogLevel)

	api, err := pcap.NewAPI(config.Buffer, config.AgentsMTLS, config.ID, config.ConcurrentCaptures)
	if err != nil {
		log.Error("Unable to create api", zap.Error(err))
		return
	}

	// set up a BoshResolver, if one is defined.
	err = registerBoshResolver(config.BoshResolverConfig, api)
	if err != nil {
		log.Error("could not register BOSH Resolver", zap.Error(err))
		return
	}

	//TODO: CFAgentResolver

	if len(api.HealthyResolverNames()) == 0 {
		log.Error("could not register any AgentResolvers. Please check the configuration.")
		return
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", config.Listen.Port))
	if err != nil {
		log.Error("unable to create listener", zap.Error(err))
		return
	}

	tlsConfig, err := config.NodeConfig.Listen.TLS.Config()
	if err != nil {
		log.Error("unable to load provided TLS credentials", zap.Error(err))
		return
	}

	tlsCredentials := credentials.NewTLS(tlsConfig)

	server := grpc.NewServer(grpc.Creds(tlsCredentials))
	pcap.RegisterAPIServer(server, api)

	go pcap.StopOnSignal(log, api, server, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	log.Info("starting server")
	err = server.Serve(lis)
	if err != nil {
		log.Error("serve returned unsuccessfully", zap.Error(err))
		return
	}

	log.Info("serve returned successfully")
}

// registerBoshResolver tries to register a BoshResolver for the BOSH Director defined in config and register it in the api.
// Does nothing when no BoshResolverConfig is provided.
//
// Returns an error if the resolver cannot be initialized.
func registerBoshResolver(config *pcap.BoshResolverConfig, api *pcap.API) error {
	if config == nil {
		return nil
	}

	resolver, err := pcap.NewBoshResolver(*config)
	if err != nil {
		return err
	}
	api.RegisterResolver(resolver)
	return nil
}
