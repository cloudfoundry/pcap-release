// Package pcap-agent is the entry point for running the pcap-agent.
//
// Supported platforms are darwin and linux, either as arm64 or amd64 due to the os signals being used.
//go:build unix && (amd64 || arm64)

package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cloudfoundry/pcap-release/src/pcap"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func init() {
	// TODO: proper logging config
	l, err := zap.NewDevelopment()
	if err != nil {
		panic(err.Error())
	}
	zap.ReplaceGlobals(l)
}

func main() {
	log := zap.L().With(zap.String("component", "agent"))

	agent, err := pcap.NewAgent(log)
	if err != nil {
		log.Error("unable to create agent", zap.Error(err))
		os.Exit(1)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", 8083))
	if err != nil {
		log.Error("unable to create listener", zap.Error(err))
		os.Exit(1)
	}

	server := grpc.NewServer()
	pcap.RegisterAgentServer(server, agent)

	go waitForSignal(log, agent, server)

	log.Info("starting server")
	err = server.Serve(lis)
	if err != nil {
		log.Error("serve returned unsuccessfully", zap.Error(err))
		os.Exit(1)
	}
	log.Info("serve returned successfully")
}

// waitForSignal to tell the agent to stop processing any streams. Will first tell the agent
// to end any running streams, wait for them to terminate and gracefully stop the gRPC server
// afterwards. Currently listens for SIGUSR1 and SIGINT.
func waitForSignal(log *zap.Logger, agent *pcap.Agent, server *grpc.Server) {
	signals := make(chan os.Signal)
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
