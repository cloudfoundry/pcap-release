// Package pcap-agent is the entry point for running the pcap-agent.
//
// Supported platforms are darwin and linux, either as arm64 or amd64 due to the os signals being used.
//go:build unix && (amd64 || arm64)

package main

import (
	"github.com/cloudfoundry/pcap-release/src/pcap"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
)

func init() {
	l, err := zap.NewDevelopment()
	if err != nil {
		panic(err.Error())
	}
	zap.ReplaceGlobals(l)
}

func main() {
	agent, err := pcap.NewAgent()
	if err != nil {
		zap.L().Error("unable to create agent", zap.Error(err))
		os.Exit(1)
	}

	waitForDraining(agent)

	err = agent.Listen(8080)
	if err != nil {
		zap.L().Error("listen returned unsuccessfully", zap.Error(err))
		os.Exit(1)
	}
}

func waitForDraining(agent *pcap.Agent) {
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGUSR1)
	go func() {
		for {
			sig := <-signals
			switch sig {
			case syscall.SIGUSR1:
				// now we are draining
				agent.Draining()
			default:
				zap.L().Warn("unknown signal", zap.String("signal", sig.String()))
			}
		}
	}()
}
