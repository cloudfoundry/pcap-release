package pcap

import (
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type Stoppable interface {
	Stop()
	Wait()
}

// WaitForSignal to tell the process to stop processing any streams. Will first tell the agent
// to end any running streams, wait for them to terminate and gracefully stop the gRPC server
// afterwards. Currently listens for SIGUSR1 and SIGINT, SIGQUIT and SIGTERM.
func WaitForSignal(log *zap.Logger, stoppable Stoppable, server *grpc.Server) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	for {
		sig := <-signals
		switch sig {
		case syscall.SIGUSR1, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM:
			log.Info("received signal, stopping.", zap.String("signal", sig.String()))
			stoppable.Stop()

			log.Info("waiting for stop")
			stoppable.Wait()

			if server != nil {
				log.Info("shutting down server")
				server.GracefulStop()
			}
			return
		default:
			log.Warn("ignoring unknown signal", zap.String("signal", sig.String()))
		}
	}
}