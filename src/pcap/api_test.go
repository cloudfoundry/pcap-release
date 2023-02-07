package pcap

import (
	"context"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"io"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
)

// Add test for capture options

//{
//name:        "Request Capture Options not complete",
//req:         &BoshRequest{Payload: &BoshRequest_Start{Start: &StartBoshCapture{Token: "123d24", Deployment: "cf", Groups: []string{"router"}}}},
//wantErr:     true,
//expectedErr: errNilField,
//},

type mockCaptureStream struct {
	msg *CaptureResponse
	err error
}

func (m *mockCaptureStream) Recv() (*CaptureResponse, error) {
	return m.msg, m.err
}

func (m *mockCaptureStream) Send(*AgentRequest) error {
	return nil
}

func (m *mockCaptureStream) CloseSend() error {
	return nil
}
func TestReadMsg(t *testing.T) {
	tests := []struct {
		name             string
		captureStream    captureReceiver
		target           AgentEndpoint
		contextCancelled bool
		expectedData     MessageType
	}{
		{
			name:             "EOF during capture",
			captureStream:    &mockCaptureStream{nil, io.EOF},
			target:           AgentEndpoint{IP: "172.20.0.2"},
			contextCancelled: false,
			expectedData:     MessageType_CAPTURE_STOPPED,
		},
		{
			name:             "Unexpected error from capture stream",
			captureStream:    &mockCaptureStream{nil, errorf(codes.Unknown, "unexpected error")},
			target:           AgentEndpoint{IP: "172.20.0.2"},
			contextCancelled: false,
			expectedData:     MessageType_CONNECTION_ERROR,
		},
		{
			name:             "Capture stop request from client and capture stopped with EOF",
			captureStream:    &mockCaptureStream{nil, io.EOF},
			target:           AgentEndpoint{IP: "172.20.0.2"},
			contextCancelled: true,
			expectedData:     MessageType_CAPTURE_STOPPED,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ctx, cancel := WithCancelCause(ctx)
			if tt.contextCancelled {
				cancel(nil)
			}

			wg := &sync.WaitGroup{}
			wg.Add(1)

			out := readMsgFromStream(ctx, tt.captureStream, tt.target)

			var got MessageType

			for s := range out {
				got = s.GetPayload().(*CaptureResponse_Message).Message.GetType()
			}

			if got != tt.expectedData {
				t.Errorf("Expected %s but got %s ", tt.expectedData, got)
			}
		})
	}
}

func TestCheckAgentStatus(t *testing.T) {
	tests := []struct {
		name      string
		statusRes *StatusResponse
		err       error
		wantErr   bool
	}{

		{
			name:      "some error during status request",
			statusRes: nil,
			err:       errEmptyField,
			wantErr:   true,
		},
		{
			name:      "agent unhealthy",
			statusRes: &StatusResponse{Healthy: false, CompatibilityLevel: CompatibilityLevel},
			err:       nil,
			wantErr:   true,
		},
		{
			name:      "agent incompatible",
			statusRes: &StatusResponse{Healthy: true, CompatibilityLevel: CompatibilityLevel - 1},
			err:       nil,
			wantErr:   true,
		},
		{
			name:      "agent healthy and compatible",
			statusRes: &StatusResponse{Healthy: true, CompatibilityLevel: CompatibilityLevel},
			err:       nil,
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkAgentStatus(tt.statusRes, tt.err, AgentEndpoint{IP: "localhost", Port: 8083})
			if (err != nil) != tt.wantErr {
				t.Errorf("checkAgentStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

type mockBoshRequestReceiver struct {
	req *CaptureRequest
	err error
}

func (m *mockBoshRequestReceiver) Recv() (*CaptureRequest, error) {
	return m.req, m.err
}
func TestStopCmd(t *testing.T) {
	tests := []struct {
		name        string
		recv        requestReceiver
		expectedErr error
		wantErr     bool
	}{
		{
			name:        "EOF during reading of message",
			recv:        &mockBoshRequestReceiver{req: nil, err: io.EOF},
			expectedErr: io.EOF,
			wantErr:     true,
		},
		{
			name:        "Empty payload",
			recv:        &mockBoshRequestReceiver{req: &CaptureRequest{Operation: nil}, err: nil},
			expectedErr: errNilField,
			wantErr:     true,
		},
		{
			name:        "Empty message",
			recv:        &mockBoshRequestReceiver{req: nil, err: nil},
			expectedErr: errNilField,
			wantErr:     true,
		},
		{
			name:        "Invalid payload type",
			recv:        &mockBoshRequestReceiver{req: &CaptureRequest{Operation: &CaptureRequest_Start{Start: &StartCapture{Capture: &Capture{Capture: &Capture_Bosh{Bosh: &BoshCapture{}}}}}}, err: nil},
			expectedErr: errInvalidPayload,
			wantErr:     true,
		},
		{
			name:        "Happy path",
			recv:        &mockBoshRequestReceiver{req: &CaptureRequest{Operation: &CaptureRequest_Stop{Stop: &StopCapture{}}}, err: nil},
			expectedErr: context.Canceled,
			wantErr:     true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			ctx, cancel := WithCancelCause(ctx)
			stopCmd(cancel, test.recv)
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

func writeToChannel(captureResponses []*CaptureResponse) chan *CaptureResponse {
	chanAgent := make(chan *CaptureResponse)
	go func() {
		defer close(chanAgent)
		for _, cr := range captureResponses {
			chanAgent <- cr
		}
	}()
	return chanAgent
}
func TestMergeResponseChannels(t *testing.T) {
	tests := []struct {
		name       string
		crAgent1   []*CaptureResponse
		crAgent2   []*CaptureResponse
		wantOutLen int
	}{
		{
			name:       "each channel has one capture response",
			crAgent1:   []*CaptureResponse{newPacketResponse([]byte("ABC"))},
			crAgent2:   []*CaptureResponse{newPacketResponse([]byte("ABC"))},
			wantOutLen: 2,
		},

		{
			name:       "one channel is empty",
			crAgent1:   []*CaptureResponse{},
			crAgent2:   []*CaptureResponse{newPacketResponse([]byte("ABC"))},
			wantOutLen: 1,
		},

		{
			name:       "both channels are empty",
			crAgent1:   []*CaptureResponse{},
			crAgent2:   []*CaptureResponse{},
			wantOutLen: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chanAgent1 := writeToChannel(tt.crAgent1)
			chanAgent2 := writeToChannel(tt.crAgent2)

			cs := []<-chan *CaptureResponse{chanAgent1, chanAgent2}
			got := mergeResponseChannels(cs)
			resCount := 0
			for range got {
				resCount++
			}
			if resCount != tt.wantOutLen {
				t.Errorf("mergeResponseChannels() = %v, wantOutLen %v", resCount, tt.wantOutLen)
			}
		})
	}
}
func TestConvertStatusCodeToMsg(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantMsgType MessageType
	}{
		{
			name:        "Invalid argument error",
			err:         errorf(codes.InvalidArgument, "read message: %w", fmt.Errorf("invalid argument")),
			wantMsgType: MessageType_INVALID_REQUEST,
		},
		{
			name:        "Agent unavailable error",
			err:         errorf(codes.Unavailable, "read message: %w", fmt.Errorf("unavailable")),
			wantMsgType: MessageType_INSTANCE_DISCONNECTED,
		},
		{
			name:        "Agent internal error",
			err:         errorf(codes.Internal, "read message: %w", fmt.Errorf("internal error")),
			wantMsgType: MessageType_CONNECTION_ERROR,
		},
		{
			name:        "Agent Unknown or internal error",
			err:         errorf(codes.Unknown, "read message: %w", fmt.Errorf("unknown")),
			wantMsgType: MessageType_CONNECTION_ERROR,
		},
		{
			name:        "Any other error",
			err:         errorf(codes.NotFound, "read message: %w", fmt.Errorf("unknown")),
			wantMsgType: MessageType_CONNECTION_ERROR,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertStatusCodeToMsg(tt.err, AgentEndpoint{"localhost", 8083})
			if got.GetMessage().GetType() != tt.wantMsgType {
				t.Errorf("convertStatusCodeToMsg() = %v, want %v", got.GetMessage().GetType(), tt.wantMsgType)

				t.Logf("message: %v", got.GetMessage().Message)
			}
		})
	}
}

type mockResponseSender struct {
}

func (m *mockResponseSender) Send(_ *CaptureResponse) error {
	return nil
}

type mockStreamPreparer struct {
	stream captureReceiver
	err    error
}

func (m *mockStreamPreparer) prepareStreamToTarget(context.Context, *CaptureOptions, AgentEndpoint, credentials.TransportCredentials) (captureReceiver, error) {
	return m.stream, m.err
}

func TestCapture(t *testing.T) {
	tests := []struct {
		name           string
		targets        []AgentEndpoint
		streamPreparer streamPreparer
		opts           *CaptureOptions
		wantErr        bool
	}{
		{
			name:           "Capture cannot be started for all targets due to error",
			targets:        []AgentEndpoint{{"localhost", 8083}, {"localhost", 8084}},
			streamPreparer: &mockStreamPreparer{err: errNilField},
			opts:           &CaptureOptions{},
			wantErr:        true,
		},
		{
			name:           "Test capture finished successfully with EOF",
			targets:        []AgentEndpoint{{"localhost", 8083}, {"localhost", 8084}},
			streamPreparer: &mockStreamPreparer{stream: &mockCaptureStream{nil, io.EOF}, err: nil},
			opts:           &CaptureOptions{},
			wantErr:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zap.L()
			got, err := capture(context.Background(), &mockResponseSender{}, tt.streamPreparer, tt.opts, tt.targets, insecure.NewCredentials(), log)
			if (err != nil) != tt.wantErr && status.Code(err) != codes.FailedPrecondition {
				t.Errorf("capture() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil {
				for m := range got {
					if m.GetMessage().GetType() != MessageType_CAPTURE_STOPPED {
						t.Errorf("capture() message type = %v, wantErr %v", m.GetMessage().GetType(), MessageType_CAPTURE_STOPPED)
					}
				}
			}
		})
	}
}
