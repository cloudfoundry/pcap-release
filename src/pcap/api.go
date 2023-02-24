package pcap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type API struct {
	// done is used to gracefully shut down the api, all captures terminate
	// whenever this channel is closed.
	done chan struct{}
	// captureWG tracks any running capture requests.
	// TODO: expose as metric?
	captureWG sync.WaitGroup
	bufConf   BufferConf
	handlers  map[string]CaptureHandler
	agents    AgentMTLS
	// ID of the instance where the api is located.
	id                    string
	maxConcurrentCaptures int
	concurrentStreams     atomic.Int32
	tlsCredentials        credentials.TransportCredentials

	UnimplementedAPIServer
}

func NewAPI(bufConf BufferConf, agentmTLS AgentMTLS, id string, maxConcurrentCaptures int) (*API, error) {
	var err error

	api := &API{
		done:                  make(chan struct{}),
		bufConf:               bufConf,
		handlers:              make(map[string]CaptureHandler),
		agents:                agentmTLS,
		id:                    id,
		maxConcurrentCaptures: maxConcurrentCaptures,
	}

	api.tlsCredentials, err = api.loadTLSCredentials()
	if err != nil {
		return nil, fmt.Errorf("create api failed: %w", err)
	}

	return api, nil
}

// AgentEndpoint defines the endpoint for a pcap-agent.
type AgentEndpoint struct {
	IP         string
	Port       int
	Identifier string
}

func (a AgentEndpoint) String() string {
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// CaptureHandler defines handlers for different request types that ultimately lead to a selection of AgentEndpoints.
type CaptureHandler interface {
	// name provides the name of the handler for outputs and internal mapping.
	name() string
	// canHandle determines if this handler is responsible for handling the Capture
	canHandle(*Capture) bool
	// handle either resolves and returns the agents targeted by Capture or provides an error
	handle(*Capture, *zap.Logger) ([]AgentEndpoint, error)
}

func (api *API) RegisterHandler(handler CaptureHandler) {
	api.handlers[handler.name()] = handler
}

// Status provides the current status information for the pcap-api service.
func (api *API) Status(context.Context, *StatusRequest) (*StatusResponse, error) {
	bosh := api.handlerRegistered("bosh")
	cf := api.handlerRegistered("cf")

	apiStatus := &StatusResponse{
		Healthy:            !api.draining(),
		CompatibilityLevel: 0,
		Message:            "Ready.",
		Bosh:               &bosh,
		Cf:                 &cf,
	}

	if api.draining() {
		apiStatus.Message = "api has been stopped and is draining remaining capture requests"
	}

	return apiStatus, nil
}

// handlerRegistered checks if handler is registered.
// returns false, if the handler is not registered.
func (api *API) handlerRegistered(handler string) bool {
	_, ok := api.handlers[handler]
	return ok
}

// Stop the server. This will gracefully stop any captures that are currently running
// by closing API.done. Further calls to Stop have no effect.
func (api *API) Stop() {
	select {
	case <-api.done:
		// if the channel is already closed, we do nothing
	default:
		// otherwise the channel is still open and we close it
		close(api.done)
	}
}

// Wait for all open capture requests to terminate.
func (api *API) Wait() {
	api.captureWG.Wait()
}

// draining returns true after API.Stop has been called.
func (api *API) draining() bool {
	select {
	case <-api.done:
		// we only get here if the channel is closed since it is never written to
		return true
	default:
		// channel is still open
		return false
	}
}

// Capture receives messages (start or stop capture) from the client and streams payload (messages or pcap data) back.
func (api *API) Capture(stream API_CaptureServer) (err error) {
	api.captureWG.Add(1)
	defer api.captureWG.Done()

	log := zap.L().With(zap.String("handler", "capture"))

	defer func() {
		if err != nil {
			log.Error("capture ended unsuccessfully", zap.Error(err))
		}
	}()

	if api.draining() {
		return errorf(codes.Unavailable, "api is draining")
	}

	ctx, cancel := WithCancelCause(stream.Context())
	defer func() {
		cancel(nil)
	}()

	ctx, log = setVcapID(ctx, log, nil)

	currentStreams := api.concurrentStreams.Add(1)

	defer api.concurrentStreams.Add(-1)

	if currentStreams > int32(api.maxConcurrentCaptures) {
		vcapID := ctx.Value(HeaderVcapID).(string)
		return errorf(codes.ResourceExhausted, "failed starting capture with vcap-id %s: %w", vcapID, errTooManyCaptures)
	}

	log.Info("started capture stream")

	req, err := stream.Recv()
	if err != nil {
		return errorf(codes.Unknown, "unable to receive message: %w", err)
	}

	opts, isStart := req.Operation.(*CaptureRequest_Start)
	if !isStart {
		return errorf(codes.InvalidArgument, "expected start message, got %v: %w", req.Operation, errUnexpectedMessage)
	}

	targets, resolveErr := api.resolveAgentEndpoints(opts.Start.Capture, log)
	if errors.Is(resolveErr, errValidationFailed) {
		return errorf(codes.InvalidArgument, "capture targets not found: %w", err)
	}

	// Start capture
	out, err := api.capture(ctx, stream, opts.Start.Options, targets, log, connectToTarget)
	if err != nil {
		return err
	}

	forwardWG := &sync.WaitGroup{}
	forwardWG.Add(1)

	forwardToStream(cancel, out, stream, api.bufConf, forwardWG, api.id)

	// Wait for capture stop
	stopCmd(cancel, stream)

	select {
	case <-ctx.Done():
		// nothing to do, stream was terminated
	case <-api.done:
		// api shutting down
		cancel(errDraining)
		// just to be sure that the error was already propagated
		<-ctx.Done()
	}

	err = Cause(ctx)
	// Cancelling the context with nil causes context.Cancelled to be set
	// which is a non-error in our case.
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, errDraining) {
		return err
	}

	forwardWG.Wait()

	return nil
}

func (api *API) loadTLSCredentials() (credentials.TransportCredentials, error) {
	if api.agents.MTLS == nil || api.agents.MTLS.SkipVerify {
		return insecure.NewCredentials(), nil
	}

	// Load certificate of the CA who signed agent's certificate
	pemAgentCA, readErr := os.ReadFile(api.agents.MTLS.CertificateAuthority)
	if readErr != nil {
		return nil, fmt.Errorf("load agent CA's certificate failed: %w", readErr)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemAgentCA) {
		return nil, fmt.Errorf("failed to add agent CA's certificate")
	}

	// Create the credentials and return it
	config := &tls.Config{
		RootCAs:    certPool,
		ServerName: api.agents.MTLS.CommonName,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	// Load client's certificate and private key
	if api.agents.MTLS.Certificate != "" && api.agents.MTLS.PrivateKey != "" {
		clientCert, err := tls.LoadX509KeyPair(api.agents.MTLS.Certificate, api.agents.MTLS.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("load API client certificate or private key failed: %w", err)
		}

		config.Certificates = []tls.Certificate{clientCert}
	}

	return credentials.NewTLS(config), nil
}

// resolveAgentEndpoints tries all registered api.handlers until one responds or none can be found that
// support this capture request. The responsible handler is then queried for the applicable pcap-agent endpoints corresponding to this capture request.
func (api *API) resolveAgentEndpoints(capture *Capture, log *zap.Logger) ([]AgentEndpoint, error) {
	for name, handler := range api.handlers {
		if handler.canHandle(capture) {
			log.Debug("resolving agent endpoints")

			agents, err := handler.handle(capture, log)
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

// Takes the data received for each of the pcap-agents and merges it into the resulting channel
// The resulting channel is unbuffered.
// inspired by: https://go.dev/blog/pipelines
func mergeResponseChannels(cs []<-chan *CaptureResponse, bufSize int) <-chan *CaptureResponse {
	var wg sync.WaitGroup
	out := make(chan *CaptureResponse, bufSize)

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

// connectToTarget creates connection to the agent, if the agent is available and healthy, and start the Agent.Capture.
func connectToTarget(ctx context.Context, req *CaptureOptions, target AgentEndpoint, creds credentials.TransportCredentials, log *zap.Logger) (captureReceiver, error) {
	cc, err := grpc.Dial(target.String(), grpc.WithTransportCredentials(creds))
	if err != nil {
		err = fmt.Errorf("start capture from '%s': %w", target, err)
		return nil, err
	}

	agent := NewAgentClient(cc)

	statusRes, err := agent.Status(ctx, &StatusRequest{})
	err = checkAgentStatus(statusRes, err, target)
	if err != nil {
		return nil, err
	}

	agentContext := context.Background()

	vcapID, ok := ctx.Value(HeaderVcapID).(string)
	if !ok {
		agentContext, _ = setVcapID(agentContext, log, nil)
	} else {
		agentContext, _ = setVcapID(agentContext, log, &vcapID)
	}

	captureStream, err := agent.Capture(agentContext)
	if err != nil {
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
		return nil, err
	}

	return captureStream, nil
}

type captureReceiver interface {
	Recv() (*CaptureResponse, error)
	Send(*AgentRequest) error
	CloseSend() error
	Context() context.Context
}

// readMsgFromStream reads Capture messages from stream and outputs them to the out channel.If the given context errors
// an AgentRequest_Stop is sent and the messages continue to be read.if context will be cancelled from other routine
// (mostly  because client requests to stop capture), the stop request will be forwarded to agent. The data from the agent will be read till stream ends with EOF.
func readMsgFromStream(ctx context.Context, captureStream captureReceiver, target AgentEndpoint, bufSize int) <-chan *CaptureResponse {
	out := make(chan *CaptureResponse, bufSize)
	stopped := false
	go func() {
		defer close(out)
		defer func(captureStream captureReceiver) {
			closeSendErr := captureStream.CloseSend()
			if closeSendErr != nil {
				out <- convertStatusCodeToMsg(closeSendErr, target.Identifier)
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
					out <- convertStatusCodeToMsg(err, target.Identifier)
					return
				}
			}
			msg, err := captureStream.Recv()
			if err != nil && errors.Is(err, io.EOF) {
				msg := fmt.Sprintf("Capturing stopped on agent pcap-agent %s", target)
				out <- newMessageResponse(MessageType_CAPTURE_STOPPED, msg, target.Identifier)
				return
			}
			if err != nil {
				msg := fmt.Sprintf("Capturing stopped on agent pcap-agent %s", target)
				out <- newMessageResponse(MessageType_INSTANCE_UNAVAILABLE, msg, target.Identifier)
				return
			}
			code := status.Code(err)
			if code != codes.OK {
				out <- convertStatusCodeToMsg(err, target.Identifier)
				return
			}
			out <- msg
		}
	}()
	return out
}

// requestReceiver is an interface used by boshStopCmd to simplify testing.
type requestReceiver interface {
	Recv() (*CaptureRequest, error)
}

// stopCmd reads the next message from the stream. It ensures that the message
// has a payload of StopCapture. If any error is encountered or the payload is
// of a different type an appropriate cause is set and the cancel function is called.
func stopCmd(cancel CancelCauseFunc, stream requestReceiver) {
	go func() {
		msg, err := stream.Recv()
		if err != nil {
			cancel(errorf(codes.Unknown, "read message: %w", err))
			return
		}

		if msg == nil || msg.Operation == nil {
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

type streamPreparer func(context.Context, *CaptureOptions, AgentEndpoint, credentials.TransportCredentials, *zap.Logger) (captureReceiver, error)

func (api *API) capture(ctx context.Context, stream responseSender, opts *CaptureOptions, targets []AgentEndpoint, log *zap.Logger, fn streamPreparer) (<-chan *CaptureResponse, error) {
	var captureCs []<-chan *CaptureResponse
	runningCaptures := 0

	patchedFilter, err := patchFilter(opts.Filter)
	if err != nil {
		return nil, errorf(codes.FailedPrecondition, "Expanding the pcap filter to exclude traffic to pcap-api failed: %w", err)
	}

	opts.Filter = patchedFilter

	for _, target := range targets {
		log = log.With(zap.String("target", target.String()))
		log.Info("starting capture")

		var captureStream captureReceiver
		captureStream, err = fn(ctx, opts, target, api.tlsCredentials, log)
		if err != nil {
			errMsg := convertStatusCodeToMsg(err, target.Identifier)
			sendErr := stream.Send(errMsg)
			if sendErr != nil {
				log.Error(fmt.Sprintf("cannot send error to receiver: %s", errMsg.String()))
			}

			log.Info("capture cannot be started")

			continue
		}

		runningCaptures++

		c := readMsgFromStream(ctx, captureStream, target, api.bufConf.Size)
		captureCs = append(captureCs, c)
	}

	if runningCaptures == 0 {
		log.Error("starting of all captures failed during stream preparation")
		return nil, errorf(codes.FailedPrecondition, "Starting of all captures failed")
	}

	// merge channels to one channel and send to forward to stream
	out := mergeResponseChannels(captureCs, api.bufConf.Size)
	return out, nil
}
