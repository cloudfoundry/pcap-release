package pcap

import (
	"context"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/metadata"
	"io"
	"testing"

	"github.com/google/gopacket"
)

var (
	errTestEnded    = fmt.Errorf("test ended")
	errDiscardedMsg = fmt.Errorf("discarding packets")
	bufSize         = 5
	bufUpperLimit   = 4
	bufLowerLimit   = 3
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
		name     string
		handle   mockPcapHandle
		wantErr  bool
		wantData string
	}{
		{
			name:     "Error during reading of packet data",
			handle:   mockPcapHandle{data: []byte{}, ci: gopacket.CaptureInfo{}, err: fmt.Errorf("error")},
			wantErr:  true,
			wantData: "",
		},
		{
			name:     "Happy path",
			handle:   mockPcapHandle{data: []byte("ABC"), ci: gopacket.CaptureInfo{}, err: nil},
			wantErr:  false,
			wantData: "ABC",
		},
		// TODO: test case where context is cancelled and readPackets has to exit
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			ctx, cancel := WithCancelCause(ctx)

			out := readPackets(ctx, cancel, &test.handle, bufSize)

			<-ctx.Done()

			err := Cause(ctx)

			if (err != nil) != test.wantErr && test.wantData == "" {
				t.Errorf("wantErr = %v, error = %v", test.wantErr, err)
			}

			if test.wantData != "" {
				data := ""
				for s := range out {
					data += string(s.GetPacket().Data)
				}
				if test.wantData != data {
					t.Errorf("Invalid data response %s", data)
				}
			}
		})
	}
}

type mockPacketSender struct {
	err        error
	resCounter int
	sentRes    int
}

func (m *mockPacketSender) Send(res *CaptureResponse) error {
	message, isMsg := res.Payload.(*CaptureResponse_Message)
	m.resCounter++

	if m.sentRes != -1 && m.sentRes == m.resCounter {
		return errTestEnded
	}
	if m.sentRes == -1 && isMsg && message.Message.Type == MessageType_CONGESTED {
		return fmt.Errorf("%w", errDiscardedMsg)
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
			stream:      &mockPacketSender{err: io.EOF, sentRes: -1},
			resToBeSent: 2,
			response:    newPacketResponse([]byte("ABC")),
			expectedErr: io.EOF,
		},
		{
			name:        "buffer is filled with PacketResponse, one Packet discarded",
			resToBeSent: bufUpperLimit + 2,
			stream:      &mockPacketSender{err: nil, sentRes: 5},
			response:    newPacketResponse([]byte("ABC")),
			expectedErr: errTestEnded,
		},
		{
			name:        "buffer is filled with MessageResponse, no packets",
			stream:      &mockPacketSender{err: nil, sentRes: bufUpperLimit + 1},
			resToBeSent: bufUpperLimit + 1,
			response:    newMessageResponse(MessageType_INSTANCE_NOT_FOUND, "invalid id"),
			expectedErr: errTestEnded,
		},
		{
			name:        "buffer is filled with PacketResponse, discarding packets",
			stream:      &mockPacketSender{err: nil, sentRes: -1},
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

			forwardToStream(cancel, src, test.stream, bufLowerLimit, bufUpperLimit)

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
		wantHealth    Health
		wantErr       bool
	}{
		{
			name:          "up and running",
			agentDraining: false,
			wantHealth:    Health_UP,
			wantErr:       false,
		},
		{
			name:          "draining",
			agentDraining: true,
			wantHealth:    Health_DRAINING,
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
			if got.Health != tt.wantHealth {
				t.Errorf("Status() health = %v, wantHealth %v", got.Health, tt.wantHealth)
			}
		})
	}
}

func TestSetVcapId(t *testing.T) {
	tests := []struct {
		name string
		md metadata.MD
		expectedLogFieldKey  string
		expectedLogFieldValue string
	}{
		{
			name: "Request without metadata",
			md: nil,
			expectedLogFieldKey: LogKeyVcapId,
		},

		{
			name: "Metadata without vcap request id",
			md: metadata.MD{},
			expectedLogFieldKey: LogKeyVcapId,
		},
		{
			name: "Metadata with vcap request id",
			md: metadata.MD{vcap_rq_id:[]string{"123"}},
			expectedLogFieldKey: LogKeyVcapId,
			expectedLogFieldValue: "123",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ctxWithMD := metadata.NewIncomingContext(ctx, tt.md)

			observedZapCore, observedLogs := observer.New(zap.InfoLevel)
			observedLogger := zap.New(observedZapCore)

			setVcapId(ctxWithMD, observedLogger)

			if observedLogs == nil || observedLogs.Len() == 0 {
				t.Fatal("No logs are written")
			}

			entry := observedLogs.All()[0]
			if len(entry.Context) == 0 {
				t.Fatal("Log entry has no context")
			}

			if entry.Context[0].Key != tt.expectedLogFieldKey {
				t.Errorf("Expected %s but got %s", tt.expectedLogFieldKey, entry.Context[0].Key)
			}
			if tt.expectedLogFieldValue != "" && entry.Context[0].String != tt.expectedLogFieldValue {
				t.Errorf("Expected %s but got %s", tt.expectedLogFieldValue, entry.Context[0].String)
			}

		})
	}
}