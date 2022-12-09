package pcap

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// metricsServer is a singleton that should only be accessed using
	// MetricsServer. It will be initialized on first call, subsequent calls
	// will return the same instance.
	metricsServer *Metrics = nil
)

type Metrics struct {
	messagesDrained prometheus.Counter
}

func MetricsServer() *Metrics {
	if metricsServer == nil {
		metricsServer = &Metrics{}
	}
	return metricsServer
}

func (m *Metrics) Serve(port int) error {
	return http.ListenAndServe(fmt.Sprintf(":%d", port), promhttp.Handler())
}

// MessageDrained increments the counter of drained messages by one.
func (m *Metrics) MessageDrained() {
	// FIXME: Why not declare all the metrics up front?
	if m.messagesDrained == nil {
		m.messagesDrained = promauto.NewCounter(prometheus.CounterOpts{
			Name: "drained-messages",
			Help: "How many messages have been drained from channels.",
		})
	}
	m.messagesDrained.Inc()
}
