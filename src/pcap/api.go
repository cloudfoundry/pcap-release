package pcap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"google.golang.org/grpc/credentials"
	"io"
	"os"
	"sync"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type API struct {
	log       *zap.Logger
	apiConf   APIConf
	agentConf AgentTLSConf
	bufConf   BufferConf
	handlers  map[string]CaptureHandler
	UnimplementedAPIServer
}

type APIConf struct {
	Targets              []AgentEndpoint
	ClientCertFile       string
	ClientPrivateKeyFile string
}

type AgentTLSConf struct {
	AgentTLSSkipVerify bool
	AgentCommonName    string
	AgentCA            string
}

func NewAPI(log *zap.Logger, bufConf BufferConf, apiConf APIConf, agentConf AgentTLSConf) (*API, error) {
	if log == nil {
		log = zap.L()
	}

	// TODO: Init, register, enable based on configuration
	handlers := map[string]CaptureHandler{
		"bosh": &BoshHandler{config: apiConf},
	}

	return &API{
		log:       log,
		bufConf:   bufConf,
		apiConf:   apiConf,
		agentConf: agentConf,
		handlers:  handlers,
	}, nil
}

// AgentEndpoint defines the endpoint for a pcap-agent.
type AgentEndpoint struct {
	Ip   string
	Port int
}

func (a AgentEndpoint) String() string {
	return fmt.Sprintf("%s:%d", a.Ip, a.Port)
}

// CaptureHandler defines handlers for different request types that ultimately lead to a selection of AgentEndpoints.
type CaptureHandler interface {
	// enabled identifies whether this handler is available and configured
	enabled() bool
	// canHandle determines if this handler is responsible for handling the Capture
	canHandle(*Capture) bool
	// handle either resolves and returns the agents targeted by Capture or provides an error
	handle(*Capture) ([]AgentEndpoint, error)
}

func (api *API) Status(context.Context, *StatusRequest) (*StatusResponse, error) {
	bosh := api.checkHandler("bosh")
	cf := api.checkHandler("cf")

	return &StatusResponse{
		Healthy:            true,
		CompatibilityLevel: 0,
		Message:            "Ready.",
		Bosh:               &bosh,
		Cf:                 &cf,
	}, nil
}

// checkHandler checks if handler is registered and if it is enabled.
// returns false, if the handler is not registered or enabled.
func (api *API) checkHandler(handler string) bool {
	if handler, ok := api.handlers[handler]; ok {
		return handler.enabled()
	}
	return false
}

func (api *API) Capture(stream API_CaptureServer) (err error) {
	// Receive and validate capture request
	api.log.Info("received new stream on Capture handler")

	ctx, cancel := WithCancelCause(stream.Context())
	defer func() {
		cancel(nil)
	}()

	defer func() {
		if err != nil {
			api.log.Error("capture ended unsuccessfully", zap.Error(err))
		}
	}()

	req, err := stream.Recv()
	if err != nil {
		return errorf(codes.Unknown, "unable to receive message: %w", err)
	}

	if opts, isStart := req.Operation.(*CaptureRequest_Start); isStart {

		targets, err := api.resolveAgentEndpoints(opts.Start.Capture)
		if errors.Is(err, errValidationFailed) {
			return errorf(codes.InvalidArgument, "capture targets not found: %w", err)
		}

		if err != nil {
			return err
		}

		creds, err := api.prepareTLSToAgent()
		if err != nil {
			return err
		}

		streamPreparer := &streamPrep{}

		// Start capture
		out, err := capture(ctx, stream, streamPreparer, opts.Start.Options, targets, creds, api.log)
		if err != nil {
			return err
		}

		forwardWG := &sync.WaitGroup{}
		forwardWG.Add(1)

		forwardToStream(cancel, out, stream, api.bufConf, forwardWG)

		// Wait for capture stop
		stopCmd(cancel, stream)

		err = Cause(ctx)
		// Cancelling the context with nil causes context.Cancelled to be set
		// which is a non-error in our case.
		if err != nil {
			return err
		}

		forwardWG.Wait()
	}

	// TODO: Handle isStop.

	return nil
}

func (api *API) prepareTLSToAgent() (credentials.TransportCredentials, error) {
	if api.agentConf.AgentTLSSkipVerify {
		return insecure.NewCredentials(), nil
	}

	// Load certificate of the CA who signed agent's certificate
	pemAgentCA, err := os.ReadFile(api.agentConf.AgentCA)
	if err != nil {
		api.log.Error("Load Agent CA certificate failed")
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemAgentCA) {
		return nil, fmt.Errorf("failed to add agent CA's certificate")
	}

	// Create the credentials and return it
	config := &tls.Config{
		RootCAs:    certPool,
		ServerName: api.agentConf.AgentCommonName,
	}

	// Load client's certificate and private key
	if api.apiConf.ClientCertFile != "" && api.apiConf.ClientPrivateKeyFile != "" {
		clientCert, err := tls.LoadX509KeyPair(api.apiConf.ClientCertFile, api.apiConf.ClientPrivateKeyFile)
		if err != nil {
			api.log.Error("Load API client certificate or private key failed")
			return nil, err
		}
		config.Certificates = []tls.Certificate{clientCert}
	}

	return credentials.NewTLS(config), nil
}

// resolveAgentEndpoints tries all registered api.handlers until one responds or none can be found that
// support this capture request. The responsible handler is then queried for the applicable pcap-agent endpoints corresponding to this capture request.
func (api *API) resolveAgentEndpoints(capture *Capture) ([]AgentEndpoint, error) {
	for name, handler := range api.handlers {
		if handler.canHandle(capture) {
			api.log.Info("Handling request via", zap.String("handler", "name"), zap.Any("capture", capture))

			agents, err := handler.handle(capture)
			if err != nil {
				return nil, fmt.Errorf("error while handling %v via %s: %w", capture, name, err)
			}

			return agents, nil
		}
	}

	return nil, fmt.Errorf("no handler for %v", capture)
}

func checkAgentStatus(statusRes *StatusResponse, err error, target AgentEndpoint) error {
	if err != nil {
		err = fmt.Errorf("status request finished with error for '%s': %w", target, err)
		return err
	}

	if !(statusRes.Healthy) {
		statusErr := fmt.Errorf("agent unhealthy '%s': %s", target, statusRes.Message)
		return statusErr
	}

	if CompatibilityLevel > statusRes.CompatibilityLevel {
		statusErr := fmt.Errorf("incompatible versions for '%s': expected compatibility level %d+ but got %d ", target, CompatibilityLevel, statusRes.CompatibilityLevel)
		return statusErr
	}
	return nil
}

func mergeResponseChannels(cs []<-chan *CaptureResponse) <-chan *CaptureResponse {
	var wg sync.WaitGroup
	out := make(chan *CaptureResponse)

	// Start an output goroutine for each input channel in cs.  output
	// copies values from c to out until c is closed, then calls wg.Done.
	output := func(c <-chan *CaptureResponse) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(cs))
	for _, c := range cs {
		go output(c)
	}

	// Start a goroutine to close out once all the output goroutines are done.
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

type streamPrep struct {
}

// prepareStreamToTarget creates a client connection to the given target, contacts the client API for the Agent service
// to start the Capture.
func (p *streamPrep) prepareStreamToTarget(ctx context.Context, req *CaptureOptions, target AgentEndpoint, creds credentials.TransportCredentials) (captureReceiver, error) {
	cc, err := grpc.Dial(target.String(), grpc.WithTransportCredentials(creds))
	if err != nil {
		err = fmt.Errorf("start capture from '%s': %w", target, err)
		// out <- newMessageResponse(MessageType_START_CAPTURE_FAILED, err.Error())
		return nil, err
	}

	agent := NewAgentClient(cc)

	statusRes, err := agent.Status(ctx, &StatusRequest{})
	err = checkAgentStatus(statusRes, err, target)
	if err != nil {
		return nil, err
	}

	// Do not use the same context as for readMsgFromStream. Otherwise, the call of cancel function will cancel the agent
	// before the stop capture request will be sent
	captureStream, err := agent.Capture(context.Background())

	if err != nil {
		convertStatusCodeToMsg(err, target)
		return nil, err
	}

	err = captureStream.Send(&AgentRequest{
		Payload: &AgentRequest_Start{
			Start: &StartAgentCapture{
				Capture: req,
			},
		},
	})
	if err != nil {
		// out <- convertStatusCodeToMsg(err, target)
		return nil, err
	}
	return captureStream, nil
}

type captureReceiver interface {
	Recv() (*CaptureResponse, error)
	Send(*AgentRequest) error
	CloseSend() error
}

// readMsgFromStream reads Capture messages from stream and outputs them to the out channel.If the given context errors
// an AgentRequest_Stop is sent and the messages continue to be read.if context will be cancelled from other routine
// (mostly  because client requests to stop capture), the stop request will be forwarded to agent. The data from the agent will be read till stream ends with EOF.
func readMsgFromStream(ctx context.Context, captureStream captureReceiver, target AgentEndpoint) <-chan *CaptureResponse {
	out := make(chan *CaptureResponse, 100)
	stopped := false
	go func() {
		defer close(out)
		// defer wg.Done()
		defer func(captureStream captureReceiver) {
			closeSendErr := captureStream.CloseSend()
			if closeSendErr != nil {
				out <- convertStatusCodeToMsg(closeSendErr, target)
				return
			}
		}(captureStream)
		for {
			if ctx.Err() != nil && !stopped {
				stopped = true
				err := captureStream.Send(&AgentRequest{
					Payload: &AgentRequest_Stop{},
				})
				if err != nil {
					out <- convertStatusCodeToMsg(err, target)
					return
				}
			}
			msg, err := captureStream.Recv()
			if err != nil && errors.Is(err, io.EOF) {
				msg := fmt.Sprintf("Capturing stopped on agent pcap-agent %s", target)
				out <- newMessageResponse(MessageType_CAPTURE_STOPPED, msg)
				return
			}
			code := status.Code(err)
			if code != codes.OK {
				out <- convertStatusCodeToMsg(err, target)
				return
			}
			out <- msg
		}
	}()
	return out
}

func convertStatusCodeToMsg(err error, target AgentEndpoint) *CaptureResponse {
	code := status.Code(err)
	unwrappedError := errors.Unwrap(err)
	if unwrappedError != nil {
		code = status.Code(unwrappedError)
	}
	err = fmt.Errorf("capturing from agent %s: %w", target, err)

	// FIXME: internal+unknown and default are the same. Is default really a connection error?
	switch code {
	case codes.InvalidArgument:
		return newMessageResponse(MessageType_INVALID_REQUEST, err.Error())
	case codes.Aborted:
		return newMessageResponse(MessageType_INSTANCE_DISCONNECTED, err.Error())
	case codes.Internal, codes.Unknown:
		return newMessageResponse(MessageType_CONNECTION_ERROR, err.Error())
	case codes.FailedPrecondition:
		return newMessageResponse(MessageType_START_CAPTURE_FAILED, err.Error())
	case codes.ResourceExhausted:
		return newMessageResponse(MessageType_LIMIT_REACHED, err.Error())
	case codes.Unavailable:
		return newMessageResponse(MessageType_INSTANCE_NOT_FOUND, err.Error())
	default:
		return newMessageResponse(MessageType_CONNECTION_ERROR, err.Error())
	}
}

// boshRequestReceiver is an interface used by boshStopCmd to simplify testing.
type requestReceiver interface {
	Recv() (*CaptureRequest, error)
}

// stopCmd reads the next message from the stream. It ensures that the message
// has a payload of StopBoshCapture. If any error is encountered or the payload is
// of a different type an appropriate cause is set and the cancel function is called.
func stopCmd(cancel CancelCauseFunc, stream requestReceiver) {
	go func() {
		msg, err := stream.Recv()
		if err != nil {
			cancel(errorf(codes.Unknown, "read message: %w", err))
			return
		}

		if msg.GetOperation() == nil {
			cancel(errorf(codes.InvalidArgument, "read operation: operation was nil: %w", errNilField))
			return
		}

		// Gets a Stop message if it's there. Returns nil in any other case, also other message types.
		stop := msg.GetStop()
		if stop == nil {
			cancel(errorf(codes.InvalidArgument, "read operation: expected message of type Stop: %w", errInvalidPayload))
			return
		}

		// cancel without cause - normal exit
		zap.L().Debug("client requested stop of capture")
		cancel(nil)
	}()
}

type streamPreparer interface {
	prepareStreamToTarget(context.Context, *CaptureOptions, AgentEndpoint, credentials.TransportCredentials) (captureReceiver, error)
}

func capture(ctx context.Context, stream responseSender, streamPrep streamPreparer, opts *CaptureOptions, targets []AgentEndpoint, creds credentials.TransportCredentials, log *zap.Logger) (<-chan *CaptureResponse, error) {
	var captureCs []<-chan *CaptureResponse

	runningCaptures := 0
	for _, target := range targets {
		log = log.With(zap.String("target", target.String()))
		log.Info("starting capture")

		captureStream, err := streamPrep.prepareStreamToTarget(ctx, opts, target, creds)
		if err != nil {

			errMsg := convertStatusCodeToMsg(err, target)
			sendErr := stream.Send(errMsg)
			if sendErr != nil {
				return nil, sendErr
			}

			log.Info("capture cannot be started")

			continue
		}

		runningCaptures++

		log.Info("Add capture waiting group")

		c := readMsgFromStream(ctx, captureStream, target)
		captureCs = append(captureCs, c)
	}

	if runningCaptures == 0 {
		stream.Send(newMessageResponse(MessageType_START_CAPTURE_FAILED, "Starting of all captures failed"))
		log.Error("Starting of all captures failed during stream preparation")
		return nil, errorf(codes.FailedPrecondition, "Starting of all captures failed")
	}

	// merge channels to one channel and send to forward to stream
	out := mergeResponseChannels(captureCs)
	return out, nil
}
