// Package pcap-agent is the entry point for running the pcap-agent.
//
// Supported platforms are darwin and linux, either as arm64 or amd64 due to the os signals being used.
//go:build unix && (amd64 || arm64)

package main

import (
	"fmt"
	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/cloudfoundry/pcap-release/src/pcap/cmd"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func init() {
	cmd.InitZapLogger()
}

func main() {
	log := zap.L()
	log.Info("init phase done, starting agent", zap.Int64("compatibilityLevel", pcap.CompatibilityLevel))

	var err error
	var config Config
	switch len(os.Args) {
	case 1:
		config = DefaultConfig
	case 2:
		config, err = parseConfig(os.Args[1])
	default:
		err = fmt.Errorf("invalid number of arguments, expected 1 or 2 but got %d", len(os.Args))
	}
	if err != nil {
		log.Fatal("unable to load config", zap.Error(err))
	}

	err = config.validate()
	if err != nil {
		log.Fatal("unable to validate config", zap.Error(err))
	}

	agent := pcap.NewAgent(config.Buffer, config.ID)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", config.Listen.Port))
	if err != nil {
		log.Fatal("unable to create listener", zap.Error(err))
	}

	tlsCredentials, err := cmd.LoadTLSCredentials(config.CommonConfig)
	if err != nil {
		log.Fatal("unable to load provided TLS credentials", zap.Error(err))
	}

	server := grpc.NewServer(grpc.Creds(tlsCredentials))
	pcap.RegisterAgentServer(server, agent)

	go waitForSignal(log, agent, server)

	log.Info("starting server")
	err = server.Serve(lis)
	if err != nil {
		log.Fatal("serve returned unsuccessfully", zap.Error(err))
	}

	log.Info("serve returned successfully")
}

// waitForSignal to tell the agent to stop processing any streams. Will first tell the agent
// to end any running streams, wait for them to terminate and gracefully stop the gRPC server
// afterwards. Currently listens for SIGUSR1 and SIGINT.
func waitForSignal(log *zap.Logger, agent *pcap.Agent, server *grpc.Server) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGINT)
	for {
		sig := <-signals
		switch sig {
		case syscall.SIGUSR1, syscall.SIGINT:
			log.Info("received signal, stopping agent", zap.String("signal", sig.String()))
			agent.Stop()

			log.Info("waiting for agent to stop")
			agent.Wait()

			log.Info("shutting down server")
			server.GracefulStop()
			return
		default:
			log.Warn("ignoring unknown signal", zap.String("signal", sig.String()))
		}
	}
}
