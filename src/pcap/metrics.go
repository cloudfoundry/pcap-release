package pcap

import (
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// metricsServer is a singleton that should only be accessed using
	// MetricsServer. It will be initialized on first call, subsequent calls
	// will return the same instance.
	metricsServer *Metrics
)

type Metrics struct {
	messagesDrained prometheus.Counter
}

func MetricsServer() *Metrics {
	// FIXME: race condition
	if metricsServer == nil {
		metricsServer = &Metrics{
			messagesDrained: promauto.NewCounter(prometheus.CounterOpts{
				Name: "drained_messages_total",
				Help: "How many messages have been drained from channels.",
			}),
		}
		go metricsServer.Serve(8081)
	}
	return metricsServer
}

func (m *Metrics) Serve(port int) error {
	server := http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           promhttp.Handler(),
		ReadTimeout:       time.Second,
		ReadHeaderTimeout: time.Second,
		WriteTimeout:      5 * time.Second, //nolint:gomnd // this is only for the metrics server, can be hardcoded
	}
	return server.ListenAndServe()
}

// MessageDrained increments the counter of drained messages by one.
func (m *Metrics) MessageDrained() {
	m.messagesDrained.Inc()
}
