package pcap

import (
	"os"
	"os/signal"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// Stoppable provides an interface for services that can be stopped.
//
// Primarily used with StopOnSignal.
type Stoppable interface {
	Stop()
}

// WaitingStoppable adds a Wait() function to Stoppable, which allows implementing an appropriate wait.
type WaitingStoppable interface {
	Stoppable

	Wait()
}

// StopOnSignal is a reusable function to handle stop signals.
//
// The Stoppable interface defines what to do when topping a particular process, and stopSignals defines a list of
// signals, for which Stop() is called.
//
// When a server is given, it is shut down gracefully.
//
// The provided Stoppable can also be a WaitingStoppable. Then the Wait() function is also called.
func StopOnSignal(log *zap.Logger, stoppable Stoppable, server *grpc.Server, stopSignals ...os.Signal) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, stopSignals...)

	sig := <-signals

	log.Info("received signal, stopping.", zap.String("signal", sig.String()))
	stoppable.Stop()

	if waitingStoppable, ok := stoppable.(WaitingStoppable); ok {
		log.Info("waiting for stop")
		waitingStoppable.Wait()
	}

	if server != nil {
		log.Info("shutting down server")
		server.GracefulStop()
	}
}
