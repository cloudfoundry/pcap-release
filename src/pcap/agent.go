package pcap

import (
	"context"
	"fmt"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net"
	"sync"
	"sync/atomic"
)

// cause is an intermediate solution until go1.20 is released which brings
// proper support for reporting a cause when cancelling a context.
// See: https://tip.golang.org/doc/go1.20#context
type cause struct {
	m   sync.Mutex
	err error
}

// Set the given error as cause. Only the first error will be recorded,
// subsequent calls to Set do nothing.
func (c *cause) Set(e error) {
	c.m.Lock()
	defer c.m.Unlock()
	if c.err == nil {
		c.err = e
	}
}

// Get the initial error that has been recorded as cause.
func (c *cause) Get() error {
	c.m.Lock()
	defer c.m.Unlock()
	return c.err
}

type Agent struct {
	draining atomic.Bool
	// ctx can be used to stop the agent and all captures that are currently running.
	ctx context.Context
	UnimplementedAgentServer
}

func NewAgent() (*Agent, error) {
	return &Agent{
		draining: atomic.Bool{},
	}, nil
}

func (a *Agent) Draining() {
	a.draining.Store(true)
}

func (a *Agent) Listen(port int) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	server := grpc.NewServer()
	RegisterAgentServer(server, a)

	// TODO: implement a graceful stop
	return server.Serve(lis)
}

func (a *Agent) Status(ctx context.Context, req *StatusRequest) (*StatusResponse, error) {
	health := Health_UP
	if a.draining.Load() {
		health = Health_DRAINING
	}
	return &StatusResponse{
		Health:  health,
		Version: "", // TODO: decide on a way to version
		Status:  "ok",
	}, nil
}

// Capture
// TODO: write doc
func (a *Agent) Capture(stream Agent_CaptureServer) (err error) {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	log := zap.L().With(zap.String("handler", "capture"))

	defer func() {
		if err != nil {
			log.Error(err.Error())
		}
	}()

	req, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.Unknown, "unable to receive message: %s", err.Error())
	}

	err = validateAgentStartRequest(req)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, err.Error())
	}

	opts := req.Payload.(*AgentRequest_Start).Start.Capture

	log = log.With(zap.String("trace_id", req.Payload.(*AgentRequest_Start).Start.Context.TraceId))
	log.Info("starting capture", zap.String("device", opts.Device), zap.Uint32("snapLen", opts.SnapLen), zap.String("filter", opts.Filter))

	c := &cause{}

	handle, err := openHandle(opts)
	if err != nil {
		return err
	}

	// source / producer
	responses := readPackets(ctx, cancel, handle, c)
	// after this function returns we want to make sure that this channel is
	// drained properly if there is anything left in it.
	defer drain(responses)

	// sink / consumer
	forwardToStream(cancel, responses, stream, c)

	agentStopCmd(cancel, stream, c)

	<-ctx.Done()

	// FIXME(maxmoehl): with go1.20 we can add a cause to know why the capture was stopped
	// err = context.Cause(ctx)
	err = c.Get()
	if err != nil {
		return status.Error(codes.Unknown, err.Error())
	}

	log.Info("capture done")
	return nil
}

func validateAgentStartRequest(req *AgentRequest) error {
	if req == nil {
		return fmt.Errorf("invalid message: expected message to be not nil")
	}

	if req.Payload == nil {
		return fmt.Errorf("invalid message: expected payload to be not nil")
	}

	startCmd, ok := req.Payload.(*AgentRequest_Start)
	if !ok {
		return fmt.Errorf("first message must contain Payload of type StartAgentCapture")
	}

	if startCmd.Start == nil {
		return fmt.Errorf("invalid message: expected start to be not nil")
	}

	if startCmd.Start.Capture == nil {
		return fmt.Errorf("invalid message: expected capture options to be not nil")
	}

	if startCmd.Start.Context == nil {
		return fmt.Errorf("invalid message: expected capture context to be not nil")
	}

	err := startCmd.Start.Capture.validate()
	if err != nil {
		return fmt.Errorf("invalid message: %s", err.Error())
	}
	return nil
}

func openHandle(opts *CaptureOptions) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(opts.Device, int32(opts.SnapLen), true, pcap.BlockForever)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "open handle: %s", err.Error())
	}

	err = handle.SetBPFFilter(opts.Filter)
	if err != nil {
		// TODO: this could be codes.InvalidArgument since we set the user provided filter
		return nil, status.Errorf(codes.Unknown, "open handle: %s", err.Error())
	}

	return handle, nil
}

// readPackets reads from the packet source and writes them to the returned
// channel. If the given context errors the loop breaks with the next read.
// If an error is encountered while reading packets the cancel function is
// called and the loop is stopped.
func readPackets(ctx context.Context, cancel context.CancelFunc, handle *pcap.Handle, c *cause) <-chan *CaptureResponse {
	out := make(chan *CaptureResponse, 100)

	go func() {
		defer close(out)
		defer handle.Close()

		for {
			if ctx.Err() != nil {
				// This will call pcap.Handle.pcapClose which sets the underlying handle to nil.
				// doing so makes every future call to pcap.Handle.ReadPacketData return io.EOF
				// so there is no point in trying to continue reading packets. This could
				// result in lost packets.
				// See: https://github.com/google/gopacket/blob/32ee38206866f44a74a6033ec26aeeb474506804/pcap/pcap_unix.go#L251-L256
				handle.Close()
				return
			}

			data, _, err := handle.ReadPacketData()
			if err != nil {
				err = fmt.Errorf("read packet: %w", err)
				// FIXME(maxmoehl): with go1.20 we can propagate the error by using context.WithCauseCancel
				//  for now we only log the error.
				c.Set(err)
				cancel()
				return
			}

			out <- newPacketResponse(data)
		}
	}()

	return out
}

// packetSender is an interface used by forwardToStream to simplify testing.
type packetSender interface {
	Send(*CaptureResponse) error
}

// forwardToStream reads Packets form src until it's closed and writes them to stream.
// If it encounters an error while doing so the error is set to cause and the cancel function
// is called.
func forwardToStream(cancel context.CancelFunc, src <-chan *CaptureResponse, stream packetSender, c *cause) {
	go func() {
		for res := range src {
			err := stream.Send(res)
			if err != nil {
				err = fmt.Errorf("send response: %w", err)
				// FIXME(maxmoehl): with go1.20 we can propagate the error by using context.WithCauseCancel
				//  for now we only log the error.
				c.Set(err)
				cancel()
				return
			}
		}
	}()
}

// agentRequestReceiver is an interface used by agentStopCmd to simplify testing.
type agentRequestReceiver interface {
	Recv() (*AgentRequest, error)
}

// agentStopCmd reads the next message from the stream. It ensures that the message
// has a payload of StopAgentCapture. If any error is encountered or the payload is
// of a different type an appropriate cause is set and the cancel function is called.
func agentStopCmd(cancel context.CancelFunc, stream agentRequestReceiver, c *cause) {
	go func() {
		msg, err := stream.Recv()
		if err != nil {
			err = fmt.Errorf("read message: %w", err)
			// FIXME(maxmoehl): with go1.20 we can propagate the error by using context.WithCauseCancel
			//  for now we only log the error.
			c.Set(err)
			cancel()
			return
		}

		if msg == nil || msg.Payload == nil {
			err = fmt.Errorf("read message: message or payload is nil, expected Payload of type StopAgentCapture")
			// FIXME(maxmoehl): with go1.20 we can propagate the error by using context.WithCauseCancel
			//  for now we only log the error.
			c.Set(err)
			cancel()
			return
		}

		// request is empty, no need to save it
		_, ok := msg.Payload.(*AgentRequest_Stop)
		if !ok {
			err = fmt.Errorf("read payload: unexpected message, expected Payload of type StopAgentCapture")
			// FIXME(maxmoehl): with go1.20 we can propagate the error by using context.WithCauseCancel
			//  for now we only log the error.
			c.Set(err)
			cancel()
			return
		}

		// cancel without cause - normal exit
		zap.L().Debug("client requested stop of capture")
		cancel()
	}()
}
