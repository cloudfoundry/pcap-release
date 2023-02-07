package pcap

import (
	"fmt"
	"go.uber.org/zap"
)

type CloudfoundryHandler struct {
	config ManualEndpoints
}

func (cf *CloudfoundryHandler) name() string {
	return "cf"
}

func (cf *CloudfoundryHandler) canHandle(request *Capture) bool {
	return request.GetCf() != nil
}

func (cf *CloudfoundryHandler) handle(request *Capture) ([]AgentEndpoint, error) {
	zap.L().Info("Handling request for ")

	// TODO Validate & get targets from bosh

	_ = cf.config.Targets

	_ = request
	// TODO: Add the static IP addresses here, if needed
	return []AgentEndpoint{}, nil
}

func (cf *CloudfoundryHandler) validate(capture *Capture) error {
	request := capture.GetCf()

	if request == nil {
		return fmt.Errorf("invalid message: bosh: %w", errNilField)
	}

	if request.Token == "" {
		return fmt.Errorf("invalid message: token: %w", errEmptyField)
	}

	if request.AppId == "" {
		return fmt.Errorf("invalid message: application_id: %w", errEmptyField)
	}

	return nil
}
