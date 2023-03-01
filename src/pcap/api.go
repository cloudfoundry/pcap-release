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
	bufConf  BufferConf
	resolver map[string]AgentResolver
	agents   AgentMTLS
	UnimplementedAPIServer
	id string

	captures               map[string]map[string]*API_CaptureServer
	captureLock            sync.RWMutex
	maxConcurrentCaptures  int
	draining               bool
	drainTimeout           time.Duration
	agentCapturesPerVcapID map[string][]*captureReceiver
}

// TODO: This type should be removed once we have resolvers for BOSH or CF.
type ManualEndpoints struct {
	Targets []AgentEndpoint
}

func NewAPI(bufConf BufferConf, agentmTLS AgentMTLS, id string, maxConcurrentCaptures int, drainTimeout time.Duration) *API {
	return &API{
		bufConf:                bufConf,
		resolver:               make(map[string]AgentResolver),
		agents:                 agentmTLS,
		id:                     id,
		maxConcurrentCaptures:  maxConcurrentCaptures,
		captures:               make(map[string]map[string]*API_CaptureServer, concurrentCapturesPerClient),
		drainTimeout:           drainTimeout,
		agentCapturesPerVcapID: make(map[string][]*captureReceiver),
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

// AgentResolver defines resolver for different request types that ultimately lead to a selection of EndpointRequest.
type AgentResolver interface {
	// name provides the name of the resolver for outputs and internal mapping.
	name() string
	// canResolve determines if this resolver is responsible for handling the EndpointRequest
	canResolve(*EndpointRequest) bool
	// resolve either resolves and returns the agents targeted by EndpointRequest or provides an error
	resolve(*EndpointRequest, *zap.Logger) ([]AgentEndpoint, error)
}

func (api *API) RegisterResolver(resolver AgentResolver) {
	api.resolver[resolver.name()] = resolver
}

// Status provides the current status information for the pcap-api service.
func (api *API) Status(context.Context, *StatusRequest) (*StatusResponse, error) {
	bosh := api.resolverRegistered("bosh")
	cf := api.resolverRegistered("cf")

	apiStatus := &StatusResponse{
		Healthy:            !api.draining,
		CompatibilityLevel: 0,
		Message:            "Ready.",
		Bosh:               &bosh,
		Cf:                 &cf,
	}

	if api.draining {
		apiStatus.Message = "api has been stopped and is draining remaining capture requests"
	}

	return apiStatus, nil
}

// resolverRegistered checks if resolver is registered.
// returns false, if the resolver is not registered.
func (api *API) resolverRegistered(resolver string) bool {
	_, ok := api.resolver[resolver]
	return ok
}

// EndpointRequest receives messages (start or stop capture) from the client and streams payload (messages or pcap data) back.
func (api *API) Capture(stream API_CaptureServer) (err error) {
	log := zap.L().With(zap.String("resolver", "capture"))

	defer func() {
		if err != nil {
			log.Error("capture ended unsuccessfully", zap.Error(err))
		}
	}()

	if api.draining {
		return errorf(codes.Unavailable, "api is draining")
	}

	ctx, cancel := WithCancelCause(stream.Context())
	defer func() {
		cancel(nil)
	}()

	ctx, log = setVcapID(ctx, log, nil)

	err = api.registerStream(ctx, &stream)
	if err != nil {
		// too many requests in parallel.
		return errorf(codes.ResourceExhausted, "failed starting capture: %w", err)
	}

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
	if resolveErr != nil {
		//TODO: Handle other errors
		return errorf(codes.Unknown, err.Error())
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

	err = Cause(ctx)
	// Cancelling the context with nil causes context.Cancelled to be set
	// which is a non-error in our case.
	if err != nil {
		return err
	}

	forwardWG.Wait()

	api.deregisterStream(ctx, &stream)

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

// resolveAgentEndpoints tries all registered api.resolver until one responds or none can be found that
// support this capture request. The responsible resolver is then queried for the applicable pcap-agent endpoints corresponding to this capture request.
func (api *API) resolveAgentEndpoints(capture *EndpointRequest, log *zap.Logger) ([]AgentEndpoint, error) {
	for name, resolver := range api.resolver {
		if resolver.canResolve(capture) {
			log.Sugar().Debugf("Resolving agent endpoints via resolver %s for capture %s", name, capture)

			agents, err := resolver.resolve(capture, log)
			if err != nil {
				return nil, fmt.Errorf("error while resolving %v via %s: %w", capture, name, err)
			}

			return agents, nil
		}
	}

	return nil, fmt.Errorf("no resolver for %v", capture)
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
// to start the capture.
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
		// TODO implement error handling
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

// readMsgFromStream reads capture messages from stream and outputs them to the out channel.If the given context errors
// an AgentRequest_Stop is sent and the messages continue to be read.if context will be cancelled from other routine
// (mostly  because client requests to stop capture), the stop request will be forwarded to agent. The data from the agent will be read till stream ends with EOF.
func readMsgFromStream(ctx context.Context, captureStream captureReceiver, target AgentEndpoint, bufSize int) <-chan *CaptureResponse {
	out := make(chan *CaptureResponse, bufSize)
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

		err = api.registerAgentCaptureStream(ctx, &captureStream, log)
		if err != nil {
			//TODO: implement error handling
		}

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

// starts the API drain process, where all ongoing captures are sent a Stop signal so they can terminate gracefully.
// Runs with a drain timeout and will return an error if the context times out.
func (api *API) Drain() error {
	zap.L().Debug("Starting drain with timeout", zap.Duration("timeout", api.drainTimeout))
	drainTimeout, cancel := context.WithTimeout(context.Background(), api.drainTimeout)
	defer cancel()

	drained := api.drainStreams()
	for {
		select {
		case <-drained:
			zap.L().Info("Drain completed successfully.")
			return nil
		case <-drainTimeout.Done():
			zap.L().Warn("Drain timeout reached, but not all clients completed.")
			return drainTimeout.Err()
		}
	}
}

func (api *API) drainStreams() chan struct{} {
	defer api.captureLock.Unlock()
	api.captureLock.Lock()

	api.draining = true

	wg := &sync.WaitGroup{}
	for client, clientStreams := range api.captures {
		for vcapID, _ := range clientStreams {
			zap.L().Debug("Terminating capture for client", zap.String("client", client), zap.String(LogKeyVcapID, vcapID))

			err := api.drainStreamForVcapID(vcapID, wg)
			if err != nil {
				zap.S().Warn("Could not send stop request to agent capturing ", zap.String(LogKeyVcapID, vcapID), zap.Error(err))
				continue
			}
		}
	}

	drained := make(chan struct{})

	go func(wg *sync.WaitGroup) {
		wg.Wait()
		close(drained)
	}(wg)

	return drained
}

func (api *API) drainStreamForVcapID(vcapID string, wg *sync.WaitGroup) error {
	for _, agentStream := range api.agentCapturesPerVcapID[vcapID] {
		err := (*agentStream).Send(&AgentRequest{
			Payload: &AgentRequest_Stop{},
		})
		if err != nil {
			zap.S().Warn("Could not send stop request to agent capturing request with vcapId", zap.String(LogKeyVcapID, vcapID), zap.Error(err))
			continue
		}
		// The message could be sent, so we expect the context to finish gracefully.
		wg.Add(1)
		go func(wg *sync.WaitGroup, ctx context.Context) {
			// wait for capture stream context do be done
			<-ctx.Done()
			wg.Done()
		}(wg, (*agentStream).Context())
	}
	return nil
}

func (api *API) registerAgentCaptureStream(ctx context.Context, captureStream *captureReceiver, log *zap.Logger) error {
	defer api.captureLock.Unlock()
	api.captureLock.Lock()

	// register the agent capture stream if it has been started successfully
	vcapID, err := vcapIDFromOutgoingCtx(ctx)
	if err != nil {
		log.Warn("no vcap ID found")
	}

	if _, exists := api.agentCapturesPerVcapID[*vcapID]; !exists {
		api.agentCapturesPerVcapID[*vcapID] = []*captureReceiver{}
	}

	//FIXME what should be done if vcapID is not set and err occurs?
	api.agentCapturesPerVcapID[*vcapID] = append(api.agentCapturesPerVcapID[*vcapID], captureStream)
	return nil
}

func (api *API) registerStream(ctx context.Context, stream *API_CaptureServer) error {
	defer api.captureLock.Unlock()
	api.captureLock.Lock()

	client, vcapID := identifyStream(ctx, stream)

	if _, exists := api.captures[client]; !exists {
		api.captures[client] = make(map[string]*API_CaptureServer, concurrentCapturesPerClient)
	}

	if len(api.captures[client]) >= api.maxConcurrentCaptures {
		return fmt.Errorf("could not start capture for client %s with vcap-id %s: %w", client, vcapID, errTooManyCaptures)
	}
	api.captures[client][vcapID] = stream
	return nil
}

func (api *API) deregisterStream(ctx context.Context, stream *API_CaptureServer) {
	defer api.captureLock.Unlock()
	api.captureLock.Lock()

	client, vcapID := identifyStream(ctx, stream)

	if _, exists := api.agentCapturesPerVcapID[vcapID]; exists {
		delete(api.agentCapturesPerVcapID, vcapID)
	}

	if clientStreams, hasClient := api.captures[client]; hasClient {
		delete(clientStreams, vcapID)
		if len(clientStreams) == 0 {
			delete(api.captures, client)
		}
	}
}

func identifyStream(ctx context.Context, stream *API_CaptureServer) (string, string) {
	// FIXME: Use a better client identifier
	client := "client-sessions"

	vcapID, err := vcapIDFromOutgoingCtx(ctx)

	if err != nil {
		return client, "unknown"
	}

	return client, *vcapID
}
