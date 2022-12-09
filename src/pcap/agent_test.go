package pcap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var (
	errTestEnded        = fmt.Errorf("test ended")
	errContextCancelled = fmt.Errorf("context error")
	errDiscardedMsg     = fmt.Errorf("discarding packets")
	bufSize             = 5
	bufUpperLimit       = 4
	bufLowerLimit       = 3
)

type mockStreamReceiver struct {
	req *AgentRequest
	err error
}

func (m *mockStreamReceiver) Recv() (*AgentRequest, error) {
	return m.req, m.err
}

func TestAgentStopCmd(t *testing.T) {
	tests := []struct {
		name        string
		recv        agentRequestReceiver
		expectedErr error
		wantErr     bool
	}{
		{
			name:        "EOF during reading of message",
			recv:        &mockStreamReceiver{req: &AgentRequest{}, err: io.EOF},
			expectedErr: io.EOF,
			wantErr:     true,
		},
		{
			name:        "Empty payload",
			recv:        &mockStreamReceiver{req: &AgentRequest{}, err: nil},
			expectedErr: errNilField,
			wantErr:     true,
		},
		{
			name:        "Empty message",
			recv:        &mockStreamReceiver{req: nil, err: nil},
			expectedErr: errNilField,
			wantErr:     true,
		},
		{
			name:        "Invalid payload type",
			recv:        &mockStreamReceiver{req: &AgentRequest{Payload: &AgentRequest_Start{}}, err: nil},
			expectedErr: errInvalidPayload,
			wantErr:     true,
		},
		{
			name:        "Happy path",
			recv:        &mockStreamReceiver{req: &AgentRequest{Payload: &AgentRequest_Stop{}}, err: nil},
			expectedErr: context.Canceled,
			wantErr:     true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			ctx, cancel := WithCancelCause(ctx)
			agentStopCmd(cancel, test.recv)
			<-ctx.Done()

			err := Cause(ctx)

			if (err != nil) != test.wantErr {
				t.Errorf("wantErr = %v, error = %v", test.wantErr, err)
			}

			if test.expectedErr != nil && !errors.Is(err, test.expectedErr) {
				t.Errorf("expectedErr = %v, error = %v", test.expectedErr, err)
			}
		})
	}
}

type mockPcapHandle struct {
	data   []byte
	ci     gopacket.CaptureInfo
	err    error
	called bool
}

func (m *mockPcapHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if m.called {
		return nil, gopacket.CaptureInfo{}, errTestEnded
	}
	m.called = true
	return m.data, m.ci, m.err
}

func (m *mockPcapHandle) Close() {
	// do nothing
}

func TestReadPackets(t *testing.T) {
	tests := []struct {
		name             string
		handle           mockPcapHandle
		contextCancelled bool
		expectedErr      error
		expectedData     string
	}{
		{
			name:             "Error during reading of packet data",
			handle:           mockPcapHandle{data: []byte{}, ci: gopacket.CaptureInfo{}, err: io.EOF},
			contextCancelled: false,
			expectedErr:      io.EOF,
		},
		{
			name:             "Error context cancelled",
			handle:           mockPcapHandle{data: []byte{}, ci: gopacket.CaptureInfo{}, err: nil},
			contextCancelled: true,
			expectedErr:      errContextCancelled,
		},
		{
			name:             "Happy path",
			handle:           mockPcapHandle{data: []byte("ABC"), ci: gopacket.CaptureInfo{}, err: nil},
			contextCancelled: false,
			expectedData:     "ABC",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			ctx, cancel := WithCancelCause(ctx)
			if test.contextCancelled {
				// cancel context before read packets in order to get edge case
				cancel(errContextCancelled)
			}

			out := readPackets(ctx, cancel, &test.handle, bufSize)

			<-ctx.Done()

			err := Cause(ctx)
			if err != nil && !errors.Is(err, test.expectedErr) && !errors.Is(err, errTestEnded) {
				t.Errorf("expectedErr = %v, got err = %v", test.expectedErr, err)
			}

			if test.expectedData != "" {
				data := ""
				for s := range out {
					data += string(s.GetPacket().Data)
				}
				if test.expectedData != data {
					t.Errorf("Invalid data response %s", data)
				}
			}
		})
	}
}

type mockPacketSender struct {
	err                  error
	resCounter           int
	sentRes              int
	stopAfterErrorOccurs bool
}

func (m *mockPacketSender) Send(res *CaptureResponse) error {
	message, isMsg := res.Payload.(*CaptureResponse_Message)
	m.resCounter++

	if m.stopAfterErrorOccurs && isMsg && message.Message.Type == MessageType_CONGESTED {
		return fmt.Errorf("%w", errDiscardedMsg)
	}

	if !m.stopAfterErrorOccurs && m.sentRes == m.resCounter {
		return errTestEnded
	}

	return m.err
}

func TestForwardToStream(t *testing.T) {
	tests := []struct {
		name        string
		resToBeSent int
		stream      responseSender
		response    *CaptureResponse
		expectedErr error
	}{
		{
			name:        "error during sending of packets",
			stream:      &mockPacketSender{err: io.EOF, stopAfterErrorOccurs: true},
			resToBeSent: 2,
			response:    newPacketResponse([]byte("ABC")),
			expectedErr: io.EOF,
		},
		{
			name:        "buffer is filled with PacketResponse, one packet discarded",
			stream:      &mockPacketSender{err: nil, sentRes: bufUpperLimit + 1},
			resToBeSent: bufUpperLimit + 2,
			response:    newPacketResponse([]byte("ABC")),
			expectedErr: errTestEnded,
		},
		{
			name:        "buffer is filled with MessageResponse, no packets discarded",
			stream:      &mockPacketSender{err: nil, sentRes: bufUpperLimit + 1},
			resToBeSent: bufUpperLimit + 1,
			response:    newMessageResponse(MessageType_INSTANCE_NOT_FOUND, "invalid id"),
			expectedErr: errTestEnded,
		},
		{
			name:        "buffer is filled with PacketResponse, discarding packets",
			stream:      &mockPacketSender{err: nil, stopAfterErrorOccurs: true},
			resToBeSent: bufUpperLimit + 1,
			response:    newPacketResponse([]byte("ABC")),
			expectedErr: errDiscardedMsg,
		},
		{
			name:        "happy path",
			stream:      &mockPacketSender{err: nil, sentRes: bufUpperLimit - 1},
			resToBeSent: bufUpperLimit - 1,
			response:    newPacketResponse([]byte("ABC")),
			expectedErr: errTestEnded,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			ctx, cancel := WithCancelCause(ctx)
			src := make(chan *CaptureResponse, bufSize)
			defer close(src)
			go func() {
				for i := 0; i < test.resToBeSent; i++ {
					src <- test.response
				}
			}()

			wg := &sync.WaitGroup{}
			wg.Add(1)

			forwardToStream(cancel, src, test.stream, BufferConf{Size: 5, UpperLimit: 4, LowerLimit: 3}, wg)

			<-ctx.Done()

			err := Cause(ctx)
			if err == nil {
				t.Errorf("Expected error to finish test")
			}
			if !errors.Is(err, test.expectedErr) {
				t.Errorf("forwardToStream() expectedErr = %v, error = %v", test.expectedErr, err)
			}
		})
	}
}

func TestValidateAgentStartRequest(t *testing.T) {
	tests := []struct {
		name        string
		req         *AgentRequest
		wantErr     bool
		expectedErr error
	}{
		{
			name:        "Request is nil",
			req:         nil,
			wantErr:     true,
			expectedErr: errNilField,
		},
		{
			name:        "Request Payload is nil",
			req:         &AgentRequest{},
			wantErr:     true,
			expectedErr: errNilField,
		},
		{
			name:        "Request Payload invalid type",
			req:         &AgentRequest{Payload: &AgentRequest_Stop{}},
			wantErr:     true,
			expectedErr: errInvalidPayload,
		},
		{
			name:        "Request Payload start is nil",
			req:         &AgentRequest{Payload: &AgentRequest_Start{}},
			wantErr:     true,
			expectedErr: errNilField,
		},
		{
			name:        "Request Payload start is nil",
			req:         &AgentRequest{Payload: &AgentRequest_Start{&StartAgentCapture{}}},
			wantErr:     true,
			expectedErr: errNilField,
		},
		{
			name:        "Request Payload capture options is nil",
			req:         &AgentRequest{Payload: &AgentRequest_Start{Start: &StartAgentCapture{}}},
			wantErr:     true,
			expectedErr: errNilField,
		},
		{
			name:        "Request Payload capture options invalid",
			req:         &AgentRequest{Payload: &AgentRequest_Start{Start: &StartAgentCapture{Capture: &CaptureOptions{Device: "", Filter: "", SnapLen: 0}}}},
			wantErr:     true,
			expectedErr: nil,
		},
		{
			name:        "Happy path",
			req:         &AgentRequest{Payload: &AgentRequest_Start{Start: &StartAgentCapture{Capture: &CaptureOptions{Device: "en0", Filter: "", SnapLen: 65000}}}},
			wantErr:     false,
			expectedErr: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateAgentStartRequest(test.req)
			if (err != nil) != test.wantErr {
				t.Errorf("wantErr = %v, error = %v", test.wantErr, err)
			}
			if test.expectedErr != nil && !errors.Is(err, test.expectedErr) {
				t.Errorf("expectedErr = %v, error = %v", test.expectedErr, err)
			}
		})
	}
}

func TestAgentDraining(t *testing.T) {
	tests := []struct {
		name         string
		expectedDone bool
		want         bool
	}{
		{
			name:         "not draining",
			expectedDone: false,
			want:         false,
		},
		{
			name:         "draining",
			expectedDone: true,
			want:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := NewAgent(nil, BufferConf{bufSize, bufUpperLimit, bufLowerLimit})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectedDone {
				a.Stop()
			}
			if got := a.draining(); got != tt.want {
				t.Errorf("draining() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAgentStatus(t *testing.T) {
	tests := []struct {
		name          string
		agentDraining bool
		wantHealth    bool
		wantErr       bool
	}{
		{
			name:          "up and running",
			agentDraining: false,
			wantHealth:    true,
			wantErr:       false,
		},
		{
			name:          "draining",
			agentDraining: true,
			wantHealth:    false,
			wantErr:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := NewAgent(nil, BufferConf{bufSize, bufUpperLimit, bufLowerLimit})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.agentDraining {
				a.Stop()
			}
			got, err := a.Status(context.Background(), nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("Status() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got.Healthy != tt.wantHealth {
				t.Errorf("Status() healthy = %v, wantHealth %v", got.Healthy, tt.wantHealth)
			}
		})
	}
}

type mockCaptureServer struct {
	req *AgentRequest
	err error
	grpc.ServerStream
	context context.Context
}

func (m *mockCaptureServer) Send(res *CaptureResponse) error {
	_, _ = res.Payload.(*CaptureResponse_Message)
	return nil
}

func (m *mockCaptureServer) Recv() (*AgentRequest, error) {
	return m.req, m.err
}

func (m *mockCaptureServer) Context() context.Context {
	return m.context
}

func TestAgentCapture(t *testing.T) {
	tests := []struct {
		name           string
		stream         mockCaptureServer
		agentRunning   bool
		wantErr        bool
		wantStatusCode codes.Code
	}{
		{
			name:           "Agent is draining",
			stream:         mockCaptureServer{nil, nil, nil, context.Background()},
			agentRunning:   false,
			wantErr:        true,
			wantStatusCode: codes.Unavailable,
		},
		{
			name:           "Receiving of incoming request finished with error",
			stream:         mockCaptureServer{nil, errNilField, nil, context.Background()},
			agentRunning:   true,
			wantErr:        true,
			wantStatusCode: codes.Unknown,
		},
		{
			name:           "Incoming Request is invalid",
			stream:         mockCaptureServer{nil, nil, nil, context.Background()},
			agentRunning:   true,
			wantErr:        true,
			wantStatusCode: codes.InvalidArgument,
		},
		{
			name:           "open handle error",
			stream:         mockCaptureServer{&AgentRequest{Payload: &AgentRequest_Start{Start: &StartAgentCapture{Capture: &CaptureOptions{Device: "12as", Filter: "", SnapLen: 65000}}}}, nil, nil, context.Background()},
			agentRunning:   true,
			wantErr:        true,
			wantStatusCode: codes.Internal,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a, err := NewAgent(nil, BufferConf{bufSize, bufUpperLimit, bufLowerLimit})
			if err != nil {
				t.Errorf("Unexpected error %v", err)
			}

			if !test.agentRunning {
				a.Stop()
				time.Sleep(1 * time.Second)
			}

			err = a.Capture(&test.stream)
			if (err != nil) != test.wantErr {
				t.Errorf("Capture() error = %v, wantErr %v", err, test.wantErr)
			}

			code := status.Code(err)
			if test.wantErr && code != test.wantStatusCode {
				t.Errorf("Capture() statusCode = %v, wantStatusCode = %v", code, test.wantStatusCode)
			}
		})
	}
}

func TestSetVcapId(t *testing.T) {
	tests := []struct {
		name   string
		md     metadata.MD
		vcapID string
	}{
		{
			name: "Request without metadata",
			md:   nil,
		},

		{
			name: "Metadata without vcap request id",
			md:   metadata.MD{},
		},
		{
			name:   "Metadata with vcap request id",
			md:     metadata.MD{HeaderVcapID: []string{"123"}},
			vcapID: "123",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), tt.md)

			observedZapCore, observedLogs := observer.New(zap.InfoLevel)
			log := zap.New(observedZapCore)

			log = setVcapID(ctx, log)

			// ensure that at least one log has been observed
			log.Info("test")

			if observedLogs == nil || observedLogs.Len() == 0 {
				t.Fatal("No logs are written")
			}

			entry := observedLogs.All()[observedLogs.Len()-1]

			for _, logField := range entry.Context {
				if logField.Key == LogKeyVcapID && (tt.vcapID == "" || logField.String == tt.vcapID) {
					return
				}
			}

			t.Errorf("missing field %s or field has wrong value", LogKeyVcapID)
		})
	}
}
