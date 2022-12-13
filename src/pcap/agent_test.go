package pcap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/google/gopacket"
)

var errTestEnded = fmt.Errorf("test ended")

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
	//do nothing
}

func TestReadPackets(t *testing.T) {
	tests := []struct {
		name      string
		handle  mockPcapHandle
		wantErr  bool
		wantData string
	}{
		{
			name:     "Error during reading of packet data",
			handle:   mockPcapHandle{data: []byte{}, ci: gopacket.CaptureInfo{}, err: fmt.Errorf("Error")},
			wantErr:  true,
			wantData: "",
		},
		{
			name:     "Happy path",
			handle:   mockPcapHandle{data: []byte("ABC"), ci: gopacket.CaptureInfo{}, err: nil},
			wantErr:  false,
			wantData: "ABC",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			ctx, cancel := WithCancelCause(ctx)

			out := readPackets(ctx, cancel, &test.handle)

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
	err    error
	called bool
	msgCounter uint16
	msgCount uint16
}

func (m *mockPacketSender) Send(res *CaptureResponse) error{
	message, isMsg := res.Payload.(*CaptureResponse_Message)
    m.msgCounter++

	if isMsg && message.Message.Type == MessageType_DISCARDING_MESSAGES{
		return fmt.Errorf("%v", message.Message.Type)
	}

	if m.msgCount == m.msgCounter {
		return errTestEnded
	}

	return m.err
}

func (m *mockPacketSender) MsgCounter() uint16{
	return m.msgCounter
}


func TestForwardToStream(t *testing.T) {
	tests := []struct {
		name string
		msgCount uint16
		stream packetSender
		src chan *CaptureResponse
		responses []*CaptureResponse
		wantErr bool
		success bool
	}{
		{
			name: "error during sending of packets",
			stream: &mockPacketSender{err: fmt.Errorf("Error"), msgCount: 1},
			src: make(chan *CaptureResponse, 5),
			responses: []*CaptureResponse{newPacketResponse([]byte("ABC"))},
			wantErr: true,
			success: false,
		},
		{
			name: "buffer is filled with PacketResponse",
			msgCount: 5,
			stream: &mockPacketSender{err: nil, msgCount: 5},
			src: make(chan *CaptureResponse, 5),
			responses: []*CaptureResponse{newPacketResponse([]byte("ABC")), newPacketResponse([]byte("ABC")), newPacketResponse([]byte("ABC")), newPacketResponse([]byte("ABC")), newPacketResponse([]byte("ABC"))},
			wantErr: true,
			success: false,
		},
		{
			name: "buffer is filled with MessageResponse",
			stream: &mockPacketSender{err: nil, msgCount: 5},
			src: make(chan *CaptureResponse, 5),
			responses: []*CaptureResponse{newMessageResponse(MessageType_INSTANCE_NOT_FOUND,"invalid id"),newMessageResponse(MessageType_INSTANCE_NOT_FOUND,"invalid id"),newMessageResponse(MessageType_INSTANCE_NOT_FOUND,"invalid id"),newMessageResponse(MessageType_INSTANCE_NOT_FOUND,"invalid id"),newMessageResponse(MessageType_INSTANCE_NOT_FOUND,"invalid id")},
			wantErr: false,
			success: true,
		},
		{
			name: "happy path",
			stream: &mockPacketSender{err: nil, msgCount: 2},
			src: make(chan *CaptureResponse, 5),
			responses: []*CaptureResponse{newPacketResponse([]byte("ABC")), newPacketResponse([]byte("ABC"))},
			wantErr: false,
			success: true,
		},

	}
		for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			ctx, cancel := WithCancelCause(ctx)

			for _, res := range test.responses{
				test.src <- res
			}

			forwardToStream(cancel, test.src, test.stream)

			<-ctx.Done()

			err := Cause(ctx)
			if test.success && err != nil && !errors.Is(err, errTestEnded)  {
				t.Errorf("forwardToStream() error to be of type errTestEnded but was error = %v, wantErr %v", err, test.wantErr)
			}

			if !test.success && (err != nil) != test.wantErr {
				t.Errorf("forwardToStream() error = %v, wantErr %v", err, test.wantErr)
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
			req:         &AgentRequest{Payload: &AgentRequest_Start{Start: &StartAgentCapture{Context: &Context{TraceId: "12344"}}}},
			wantErr:     true,
			expectedErr: errNilField,
		},
		{
			name:        "Request Payload context options is nil",
			req:         &AgentRequest{Payload: &AgentRequest_Start{Start: &StartAgentCapture{Capture: &CaptureOptions{Device: "en0", Filter: "", SnapLen: 65000}}}},
			wantErr:     true,
			expectedErr: errNilField,
		},
		{
			name:        "Request Payload capture options invalid",
			req:         &AgentRequest{Payload: &AgentRequest_Start{Start: &StartAgentCapture{Capture: &CaptureOptions{Device: "", Filter: "", SnapLen: 0}, Context: &Context{TraceId: "12344"}}}},
			wantErr:     true,
			expectedErr: nil,
		},
		{
			name: "Happy path",
			req: &AgentRequest{Payload: &AgentRequest_Start{Start: &StartAgentCapture{
				Context: &Context{TraceId: "12344"},
				Capture: &CaptureOptions{Device: "en0", Filter: "", SnapLen: 65000},
			}}},
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
			a, err := NewAgent(nil)
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

func TestAgent_Status(t *testing.T) {
	tests := []struct {
		name    string
		agentDraining bool
		wantHealth    Health
		wantErr bool
	}{
		{
			name: "up and running",
			agentDraining: false,
			wantHealth: Health_UP,
            wantErr: false,
		},
		{
			name: "draining",
			agentDraining: true,
			wantHealth: Health_DRAINING,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := NewAgent(nil)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.agentDraining {
				a.Stop()
			}
			got, err := a.Status(nil, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("Status() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got.Health != tt.wantHealth {
				t.Errorf("Status() health = %v, wantHealth %v", got.Health, tt.wantHealth)
			}
		})
	}
}
