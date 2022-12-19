package pcap

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

// Agent is the central struct to which the handlers are attached.
type Agent struct {
	// done is used to gracefully shut down the agent, it will terminate all
	// ongoing streams.
	done chan struct{}
	// wg tracks any running streams.
	// TODO: expose as metric?
	wg sync.WaitGroup
	// log carries the logger all session loggers are derived from.
	log *zap.Logger

	BufferConf BufferConf

	UnimplementedAgentServer
}

// NewAgent creates a new ready-to-use agent. If the given logger is nil zap.L will
// be used.
func NewAgent(log *zap.Logger, bufConf BufferConf) (*Agent, error) {
	if log == nil {
		log = zap.L()
	}
	return &Agent{
		done:       make(chan struct{}),
		log:        log,
		BufferConf: bufConf,
	}, nil
}

// Stop the server. This will gracefully stop any captures that are currently running
// by closing Agent.done. Further calls to Stop have no effect.
func (a *Agent) Stop() {
	select {
	case <-a.done:
		// if the channel is already closed, we do nothing
	default:
		// otherwise the channel is still open and we close it
		close(a.done)
	}
}

// Wait for all open streams to terminate.
func (a *Agent) Wait() {
	a.wg.Wait()
}

func (a *Agent) draining() bool {
	select {
	case <-a.done:
		// we only get here if the channel is closed since it is never written to
		return true
	default:
		// channel is still open
		return false
	}
}

// Status handler for the pcap-agent. See AgentServer.Status documentation for details.
func (a *Agent) Status(_ context.Context, _ *StatusRequest) (*StatusResponse, error) {
	s := &StatusResponse{
		CompatibilityLevel: CompatibilityLevel,
		Health:             Health_UP,
		Status:             "ok",
	}

	if a.draining() {
		s.Health = Health_DRAINING
		s.Status = "agent is shutting down"
	}

	return s, nil
}

// Capture handler for the pcap-agent. See AgentServer.Capture documentation for details.
func (a *Agent) Capture(stream Agent_CaptureServer) (err error) {
	a.wg.Add(1)
	defer a.wg.Done()

	log := a.log.With(zap.String("handler", "capture"))
	defer func() {
		if err != nil {
			log.Error("capture ended unsuccessfully", zap.Error(err))
		}
	}()

	ctx, cancel := WithCancelCause(stream.Context())
	defer cancel(nil)

	setVcapId(ctx, log)

	if a.draining() {
		return errorf(codes.Unavailable, "agent is draining")
	}

	req, err := stream.Recv()
	if err != nil {
		return errorf(codes.Unknown, "unable to receive message: %w", err)
	}

	err = validateAgentStartRequest(req)
	if err != nil {
		return errorf(codes.InvalidArgument, "%w", err)
	}

	opts := req.Payload.(*AgentRequest_Start).Start.Capture
	log.Info("starting capture", zap.String("device", opts.Device), zap.Uint32("snapLen", opts.SnapLen), zap.String("filter", opts.Filter))

	handle, err := openHandle(opts)
	if err != nil {
		return err
	}
	defer handle.Close()

	// source / producer
	responses := readPackets(ctx, cancel, handle, a.BufferConf.Size)

	// sink / consumer
	forwardToStream(cancel, responses, stream, a.BufferConf.LowerLimit, a.BufferConf.UpperLimit)

	agentStopCmd(cancel, stream)

	select {
	case <-ctx.Done():
		// nothing to do, stream was terminated
	case <-a.done:
		// agent shutting down
		cancel(fmt.Errorf("agent was stopped"))
		// just to be sure that the error was already propagated
		<-ctx.Done()
	}

	err = Cause(ctx)
	// Cancelling the context with nil causes context.Cancelled to be set
	// which is a non-error in our case.
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	log.Info("capture done")
	// TODO: forwardToApi could still be running, we should probably introduce a wait group to wait for its termination
	return nil
}

func setVcapId(ctx context.Context, log *zap.Logger) *zap.Logger {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log = log.With(zap.String(LogKeyVcapId, uuid.Must(uuid.NewRandom()).String()))
		log.Warn("request does not contain metadata, generated vcap request id")
		return log
	}

	vcapReqId := md.Get(HeaderVcapId)
	if len(vcapReqId) == 0 {
		log = log.With(zap.String(LogKeyVcapId, uuid.Must(uuid.NewRandom()).String()))
		log.Warn("request does not contain request id, generating one")
		return log
	}
	return log.With(zap.String(LogKeyVcapId, vcapReqId[0]))
}

// validateAgentStartRequest returns an error describing the issue or nil if
// the request is valid. The returned error does not have a gRPC status associated
// with it.
func validateAgentStartRequest(req *AgentRequest) error {
	if req == nil {
		return fmt.Errorf("invalid message: message: %w", errNilField)
	}

	if req.Payload == nil {
		return fmt.Errorf("invalid message: payload: %w", errNilField)
	}

	startCmd, ok := req.Payload.(*AgentRequest_Start)
	if !ok {
		return fmt.Errorf("invalid message: expected Payload of type StartAgentCapture: %w", errInvalidPayload)
	}

	if startCmd.Start == nil {
		return fmt.Errorf("invalid message: start: %w", errNilField)
	}

	if startCmd.Start.Capture == nil {
		return fmt.Errorf("invalid message: capture options: %w", errNilField)
	}

	err := startCmd.Start.Capture.validate()
	if err != nil {
		return fmt.Errorf("invalid message: %w", err)
	}

	return nil
}

func openHandle(opts *CaptureOptions) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(opts.Device, int32(opts.SnapLen), true, pcap.BlockForever)
	if err != nil {
		return nil, errorf(codes.Internal, "open handle: %w", err)
	}

	err = handle.SetBPFFilter(opts.Filter)
	if err != nil {
		// TODO: this could be codes.InvalidArgument since we set the user provided filter
		return nil, errorf(codes.Unknown, "open handle: %w", err)
	}

	return handle, nil
}

type pcapHandle interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	Close()
}

// readPackets reads from the packet source and writes them to the returned
// channel. If the given context errors the loop breaks with the next read.
// If an error is encountered while reading packets the cancel function is
// called and the loop is stopped.
func readPackets(ctx context.Context, cancel CancelCauseFunc, handle pcapHandle, bufSize int) <-chan *CaptureResponse {
	out := make(chan *CaptureResponse, bufSize)

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
				cancel(fmt.Errorf("read packet: %w", err))
				return
			}

			out <- newPacketResponse(data)
		}
	}()

	return out
}

// responseSender is an interface used by forwardToStream to simplify testing.
type responseSender interface {
	Send(*CaptureResponse) error
}

// forwardToStream reads Packets from src until it's closed and writes them to stream.
// If it encounters an error while doing so the error is set to cause and the cancel function
// is called. Any data that is forwarded after an error is discarded.
func forwardToStream(cancel CancelCauseFunc, src <-chan *CaptureResponse, stream responseSender, lowerLimit, upperLimit int) {
	go func() {
		// After this function returns we want to make sure that this channel is
		// drained properly if there is anything left in it. This avoids responses
		// left after the connection to the client broke and no more responses are
		// read from the channel.
		defer drain(src)

		discarding := false
		for res := range src {
			// we never discard messages, only data
			_, isMsg := res.Payload.(*CaptureResponse_Message)

			// example (values are probably a bad choice):
			// buffer size: 10
			// lower limit: 2
			// upper limit: 8
			// len(src)      => fill level of buffer
			// discarding    => are we currently discarding packet responses?
			// messages sent => how many messages have been sent up until now
			// len(src) | discarding | messages sent
			// 2        | false      | 0
			// 1        | false      | 1
			// 7        | false      | 2
			// 6        | false      | 3
			// 9        | true       | 4 // last packet was DISCARDING_MESSAGES
			// 8        | true       | 4
			// 7        | true       | 4
			// ...
			// 3        | true       | 4
			// 2        | false      | 5
			// 1        | false      | 6

			switch {
			case len(src) <= lowerLimit: // if there is no buffer this case will always match
				discarding = false
			case discarding && !isMsg:
				continue
			case len(src) >= upperLimit && !isMsg:
				discarding = true
				// this only is sent when we start discarding (and discards the current data packet)
				res = newMessageResponse(MessageType_CONGESTED, "too much back pressure, discarding packets")
			}

			err := stream.Send(res)
			if err != nil {
				cancel(errorf(codes.Unknown, "send response: %w", err))
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
func agentStopCmd(cancel CancelCauseFunc, stream agentRequestReceiver) {
	go func() {
		msg, err := stream.Recv()
		if err != nil {
			cancel(errorf(codes.Unknown, "read message: %w", err))
			return
		}

		if msg == nil || msg.Payload == nil {
			cancel(errorf(codes.InvalidArgument, "read message: message or payload: %w", errNilField))
			return
		}

		// request is empty, no need to save it
		_, ok := msg.Payload.(*AgentRequest_Stop)
		if !ok {
			cancel(errorf(codes.InvalidArgument, "read payload: expected Payload of type StopAgentCapture: %w", errInvalidPayload))
			return
		}

		// cancel without cause - normal exit
		zap.L().Debug("client requested stop of capture")
		cancel(nil)
	}()
}
