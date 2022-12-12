package pcap

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"io"
	"testing"
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
		name string
		recv agentRequestReceiver
		expectedErr error
		wantedErr bool
	}{
		{
			name: "EOF during reading of message",
			recv: &mockStreamReceiver{req: &AgentRequest{}, err: io.EOF},
			expectedErr: io.EOF,
			wantedErr: true,
		},
		{
			name: "Empty payload",
			recv: &mockStreamReceiver{req: &AgentRequest{}, err: nil},
			expectedErr: errNilField,
			wantedErr: true,
		},
		{
			name: "Empty message",
			recv: &mockStreamReceiver{req: nil, err: nil},
			expectedErr: errNilField,
			wantedErr: true,
		},
		{
			name: "Invalid payload type",
			recv: &mockStreamReceiver{req: &AgentRequest{Payload: &AgentRequest_Start{}}, err: nil},
			expectedErr: errInvalidPayload,
			wantedErr: true,
		},
		{
			name: "Happy path",
			recv: &mockStreamReceiver{req: &AgentRequest{Payload: &AgentRequest_Stop{}}, err: nil},
			expectedErr: nil,
			wantedErr: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			ctx, cancel := WithCancelCause(ctx)
			agentStopCmd(cancel, test.recv)
			<- ctx.Done()

			err := Cause(ctx)

			if (err != nil) != test.wantedErr {
				t.Errorf("wantedErr = %v, error = %v", test.wantedErr, err)
			}

			if test.expectedErr != nil && !errors.Is(err, test.expectedErr){
				t.Errorf("expectedErr = %v, error = %v", test.expectedErr, err)
			}
		})
	}
}

type mockPcapHandle struct {
	data []byte
	ci gopacket.CaptureInfo
	err error
}

func (m *mockPcapHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return m.data, m.ci, m.err
}

func (m *mockPcapHandle) Close() () {
	//do nothing
}

func TestReadPackets(t *testing.T) {
	tests := []struct {
		name string
		handle mockPcapHandle
		wantedErr bool
		want string
	}{
		{
			name: "Error during reading of packet data",
			handle: mockPcapHandle{data: []byte{}, ci: gopacket.CaptureInfo{}, err: fmt.Errorf("Error")},
            wantedErr: true,
			want: "",
		},
		{
			name: "Happy path",
			handle: mockPcapHandle{data: []byte("ABC"), ci: gopacket.CaptureInfo{}, err: nil},
			wantedErr: false,
			want: "ABC",
		},


	}
		for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			ctx, cancel := WithCancelCause(ctx)
			out := readPackets(ctx, cancel, &test.handle)
			//if test.want == "" {
				<-ctx.Done()
			//} else {
			//	cancel(fmt.Errorf("Error"))
			//}

			err := Cause(ctx)
			if (err != nil) != test.wantedErr && test.want == "" {
				t.Errorf("wantedErr = %v, error = %v", test.wantedErr, err)
			}
			if test.want != "" {
				data := ""
				for s := range out {
					data += string(s.GetPacket().Data)
				}
				if test.want != data {
					t.Errorf("Invalid data response %s", data)
				}
			}

		})
	}
}

func TestValidateAgentStartRequest(t *testing.T) {

	tests := []struct {
		name    string
		req    *AgentRequest
		wantedErr bool
		expectedErr error
	}{
		{
			name: "Request is nil",
			req: nil,
			wantedErr: true,
			expectedErr: errNilField,
		},
		{
			name: "Request Payload is nil",
			req: &AgentRequest{},
			wantedErr: true,
			expectedErr: errNilField,
		},
		{
			name: "Request Payload invalid type",
			req: &AgentRequest{Payload: &AgentRequest_Stop{}},
			wantedErr: true,
			expectedErr: errInvalidPayload,
		},
		{
			name: "Request Payload start is nil",
			req: &AgentRequest{Payload: &AgentRequest_Start{&StartAgentCapture{}}},
			wantedErr: true,
			expectedErr: errNilField,
		},
		{
			name: "Request Payload capture options is nil",
			req: &AgentRequest{Payload: &AgentRequest_Start{Start: &StartAgentCapture{Context: &Context{TraceId: "12344"}}}},
			wantedErr: true,
			expectedErr: errNilField,
		},
		{
			name: "Request Payload context options is nil",
			req: &AgentRequest{Payload: &AgentRequest_Start{Start: &StartAgentCapture{Capture: &CaptureOptions{Device: "en0", Filter: "", SnapLen: 65000}}}},
			wantedErr: true,
			expectedErr: errNilField,
		},
		{
			name: "Happy path",
			req: &AgentRequest{Payload: &AgentRequest_Start{Start: &StartAgentCapture{
				Context: &Context{TraceId: "12344"},
				Capture: &CaptureOptions{Device: "en0", Filter: "", SnapLen: 65000},
			}}},
			wantedErr: false,
			expectedErr: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateAgentStartRequest(test.req)
			if (err != nil) != test.wantedErr {
				t.Errorf("wantedErr = %v, error = %v", test.wantedErr, err)
			}
			if test.expectedErr != nil && !errors.Is(err, test.expectedErr){
				t.Errorf("expectedErr = %v, error = %v", test.expectedErr, err)
			}
		})
	}
}