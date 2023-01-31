package pcap

import (
	"fmt"
	"go.uber.org/zap"
)

type BoshHandler struct {
	// TODO: add specifics for BOSH director configuration
	config APIConf
}

func (bosh *BoshHandler) enabled() bool {
	return true
}

func (bosh *BoshHandler) canHandle(request *Capture) bool {
	return request.GetBosh() != nil
}

func (bosh *BoshHandler) handle(request *Capture) ([]AgentEndpoint, error) {
	zap.L().Info("Handling request for bosh")

	err := bosh.validate(request)
	if err != nil {
		return nil, err
	}

	// TODO: This is a temporary shim and should be retrieved from the BOSH director.
	return bosh.config.Targets, nil
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
