package pcap

import (
	"fmt"

	"go.uber.org/zap"
)

type CfResolver struct {
	Config ManualEndpoints
}

func (cf *CfResolver) Name() string {
	return "cf"
}

func (cf *CfResolver) CanResolve(request *EndpointRequest) bool {
	return request.GetCf() != nil
}

func (cf *CfResolver) Resolve(request *EndpointRequest, log *zap.Logger) ([]AgentEndpoint, error) {
	log = log.With(zap.String("handler", cf.Name()))
	log.Info("Handling request")

	// TODO Validate & get targets from bosh

	_ = cf.Config.Targets

	_ = request
	// TODO: Add the static IP addresses here, if needed
	return []AgentEndpoint{}, nil
}

func (cf *CfResolver) validate(request *EndpointRequest) error {
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
