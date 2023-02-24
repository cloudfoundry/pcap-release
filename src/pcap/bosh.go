package pcap

import (
	"fmt"

	"go.uber.org/zap"
)

type BoshHandler struct {
	// TODO: add specifics for BOSH director configuration
	Config ManualEndpoints
}

func (bosh *BoshHandler) name() string {
	return "bosh"
}

func (bosh *BoshHandler) canHandle(request *Capture) bool {
	return request.GetBosh() != nil
}

func (bosh *BoshHandler) handle(request *Capture, log *zap.Logger) ([]AgentEndpoint, error) {
	log = log.With(zap.String("handler", bosh.name()))
	log.Info("handling request")

	err := bosh.validate(request)
	if err != nil {
		return nil, err
	}

	// TODO: This is a temporary shim and should be retrieved from the BOSH director.
	return bosh.Config.Targets, nil
}

func (bosh *BoshHandler) validate(capture *Capture) error {
	request := capture.GetBosh()

	if request == nil {
		return fmt.Errorf("invalid message: bosh: %w", errNilField)
	}

	if request.Token == "" {
		return fmt.Errorf("invalid message: token: %w", errEmptyField)
	}

	if request.Deployment == "" {
		return fmt.Errorf("invalid message: deployment: %w", errEmptyField)
	}

	if len(request.Groups) == 0 {
		return fmt.Errorf("invalid message: instance group(s): %w", errEmptyField)
	}

	return nil
}
