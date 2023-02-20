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
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const concurrentCapturesPerClient = 10

type API struct {
	// done is used to gracefully shut down the agent, all ongoing streams terminate
	// whenever this channel is closed.
	done chan struct{}

	bufConf  BufferConf
	handlers map[string]CaptureHandler
	agents   AgentMTLS
	UnimplementedAPIServer
	id                    string
	maxConcurrentCaptures int
	concurrentStreams     atomic.Int32
}

// TODO: This type should be removed once we have resolvers for BOSH or CF.
type ManualEndpoints struct {
	Targets []AgentEndpoint
}

func NewAPI(bufConf BufferConf, agentmTLS AgentMTLS, id string, maxConcurrentCaptures int, drainTimeout time.Duration) *API {
	return &API{
		done:                  make(chan struct{}),
		bufConf:               bufConf,
		handlers:              make(map[string]CaptureHandler),
		agents:                agentmTLS,
		id:                    id,
		maxConcurrentCaptures: maxConcurrentCaptures,
	}
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

var (
	errUnexpectedMessage = fmt.Errorf("unexpected message")
)

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
	fmt.Printf("stop api called")
	select {
	case <-api.done:
		// if the channel is already closed, we do nothing
	default:
		// otherwise the channel is still open and we close it
		close(api.done)
	}
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
	currentStreams := api.concurrentStreams.Add(1)
	defer api.concurrentStreams.Add(-1)
	if currentStreams > int32(api.maxConcurrentCaptures) {
		return errorf(codes.ResourceExhausted, "failed starting capture: %w", err)
	}

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

	log.Info("Started capture stream")

	creds, err := api.prepareTLSToAgent(log)
	if err != nil {
		return err
	}

	req, err := stream.Recv()
	if err != nil {
		return errorf(codes.Unimplemented, "unable to receive message: %w", err)
	}

	opts, isStart := req.Operation.(*CaptureRequest_Start)
	if !isStart {
		return fmt.Errorf("expected start message, got %v: %w", req.Operation, errUnexpectedMessage)
	}

	targets, resolveErr := api.resolveAgentEndpoints(opts.Start.Capture, log)
	if errors.Is(resolveErr, errValidationFailed) {
		return errorf(codes.InvalidArgument, "capture targets not found: %w", err)
	}

	streamPreparer := &streamPrep{}

	// Start capture
	out, err := api.capture(ctx, stream, streamPreparer, opts.Start.Options, targets, creds, log)
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

func (api *API) prepareTLSToAgent(log *zap.Logger) (credentials.TransportCredentials, error) {
	if api.agents.MTLS == nil || api.agents.MTLS.SkipVerify {
		return insecure.NewCredentials(), nil
	}

	// Load certificate of the CA who signed agent's certificate
	pemAgentCA, readErr := os.ReadFile(api.agents.MTLS.CertificateAuthority)
	if readErr != nil {
		log.Error("Load Agent CA certificate failed")
		return nil, readErr
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
			log.Error("Load API client certificate or private key failed")
			return nil, err
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
			log.Sugar().Debugf("Resolving agent endpoints via handler %s for capture %s", name, capture)

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

type streamPrep struct {
}

// prepareStreamToTarget creates a client connection to the given target, contacts the client API for the Agent service
// to start the Capture.
func (p *streamPrep) prepareStreamToTarget(ctx context.Context, req *CaptureOptions, target AgentEndpoint, creds credentials.TransportCredentials, log *zap.Logger) (captureReceiver, error) {
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
	vcapID, err := vcapIDFromOutgoingCtx(ctx)
	if err != nil {
		// TODO impelement error handling
	}
	agentContext, log = setVcapID(agentContext, log, vcapID)
	captureStream, err := agent.Capture(agentContext)

	if err != nil {
		convertStatusCodeToMsg(err, target)
		return nil, err
	}

	patchedFilter, err := patchFilter(req.Filter)
	if err != nil {
		err = pcapError{
			status: status.New(codes.FailedPrecondition, "Expanding the pcap filter to exclude traffic to pcap-api failed"),
			inner:  err,
		}
		convertStatusCodeToMsg(err, target)
		return nil, err
	}
	req.Filter = patchedFilter

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
				out <- newMessageResponse(MessageType_CAPTURE_STOPPED, msg, target.Identifier)
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
	if code == codes.Unknown {
		unwrappedError := errors.Unwrap(err)
		if unwrappedError != nil {
			code = status.Code(unwrappedError)
		}
	}
	err = fmt.Errorf("capturing from agent %s: %w", target, err)

	//FIXME: internal+unknown and default are the same. Is default really a connection error?
	switch code { //nolint:exhaustive // we do not need to cover all the codes here
	case codes.InvalidArgument:
		return newMessageResponse(MessageType_INVALID_REQUEST, err.Error(), target.Identifier)
	case codes.Aborted:
		return newMessageResponse(MessageType_INSTANCE_UNAVAILABLE, err.Error(), target.Identifier)
	case codes.Internal, codes.Unknown:
		return newMessageResponse(MessageType_CONNECTION_ERROR, err.Error(), target.Identifier)
	case codes.FailedPrecondition:
		return newMessageResponse(MessageType_START_CAPTURE_FAILED, err.Error(), target.Identifier)
	case codes.ResourceExhausted:
		return newMessageResponse(MessageType_LIMIT_REACHED, err.Error(), target.Identifier)
	case codes.Unavailable:
		return newMessageResponse(MessageType_INSTANCE_UNAVAILABLE, err.Error(), target.Identifier)
	default:
		return newMessageResponse(MessageType_CONNECTION_ERROR, err.Error(), target.Identifier)
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
	prepareStreamToTarget(context.Context, *CaptureOptions, AgentEndpoint, credentials.TransportCredentials, *zap.Logger) (captureReceiver, error)
}

func (api *API) capture(ctx context.Context, stream responseSender, streamPrep streamPreparer, opts *CaptureOptions, targets []AgentEndpoint, creds credentials.TransportCredentials, log *zap.Logger) (<-chan *CaptureResponse, error) {
	var captureCs []<-chan *CaptureResponse

	runningCaptures := 0
	for _, target := range targets {
		log = log.With(zap.String("target", target.String()))
		log.Info("starting capture")

		captureStream, err := streamPrep.prepareStreamToTarget(ctx, opts, target, creds, log)
		if err != nil {
			errMsg := convertStatusCodeToMsg(err, target)
			sendErr := stream.Send(errMsg)
			if sendErr != nil {
				// FIXME the return interrupts the for-loop over targets and returns in case of send error
				return nil, sendErr
			}

			log.Info("capture cannot be started")

			continue
		}

		runningCaptures++

		log.Info("Add capture waiting group")

		c := readMsgFromStream(ctx, captureStream, target, api.bufConf.Size)
		captureCs = append(captureCs, c)
	}

	if runningCaptures == 0 {
		log.Error("Starting of all captures failed during stream preparation")
		return nil, errorf(codes.FailedPrecondition, "Starting of all captures failed")
	}

	// merge channels to one channel and send to forward to stream
	out := mergeResponseChannels(captureCs, api.bufConf.Size)
	return out, nil
}
