package integration

import (
	"fmt"
	"net"

	"github.com/cloudfoundry/pcap-release/src/pcap"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,stylecheck // this is the common way to import ginkgo and gomega
	"go.uber.org/zap"
)

var TestNodeIndex = 0

// localNodeListener gives each mock gorouter a separate local IP address, so gorouters can be distinguished based on their IP address in tests.
func localNodeListener(port int) net.Listener {
	// exclude .0 and .255 as they may have special meaning.
	node := (TestNodeIndex % 254) + 1 //nolint:mnd // default IP range
	subnet := TestNodeIndex / 254     //nolint:mnd // default IP range

	TestNodeIndex++

	address := fmt.Sprintf("127.0.%d.%d:%d", subnet, node, port)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		GinkgoWriter.Printf("Fatal: Could not bind to address %s: %v", address, err)
	}

	return listener
}

func NewLocalResolver(manualEndpoints []pcap.AgentEndpoint) LocalResolver {
	return LocalResolver{manualEndpoints: manualEndpoints}
}

type LocalResolver struct {
	manualEndpoints []pcap.AgentEndpoint
}

func (l LocalResolver) Healthy() bool {
	return true
}

func (l LocalResolver) Name() string {
	return "local"
}

func (l LocalResolver) CanResolve(request *pcap.EndpointRequest) bool {
	return request.GetRequest() != nil
}

func (l LocalResolver) Resolve(_ *pcap.EndpointRequest, _ *zap.Logger) ([]pcap.AgentEndpoint, error) {
	if l.manualEndpoints != nil {
		return l.manualEndpoints, nil
	}
	return nil, fmt.Errorf("no endpoints configured")
}
