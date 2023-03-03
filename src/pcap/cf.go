package pcap

import (
	"fmt"

	"go.uber.org/zap"
)

type CloudfoundryAgentResolver struct {
	Config ManualEndpoints
}

func (cf *CloudfoundryAgentResolver) name() string {
	return "cf"
}

func (cf *CloudfoundryAgentResolver) canResolve(request *EndpointRequest) bool {
	return request.GetCf() != nil
}

func (cf *CloudfoundryAgentResolver) resolve(request *EndpointRequest, log *zap.Logger) ([]AgentEndpoint, error) {
	log = log.With(zap.String("handler", cf.name()))
	log.Info("Handling request")

	// TODO Validate & get targets from bosh

	_ = cf.Config.Targets

	_ = request
	// TODO: Add the static IP addresses here, if needed
	return []AgentEndpoint{}, nil
}

func (cf *CloudfoundryAgentResolver) validate(request *EndpointRequest) error {
	cfRequest := request.GetCf()

	if cfRequest == nil {
		return fmt.Errorf("invalid message: bosh: %w", errNilField)
	}

	if cfRequest.Token == "" {
		return fmt.Errorf("invalid message: token: %w", errEmptyField)
	}

	if cfRequest.AppId == "" {
		return fmt.Errorf("invalid message: application_id: %w", errEmptyField)
	}

	return nil
}
