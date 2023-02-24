package pcap

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Add test for capture options

// {
// name:        "Request Capture Options not complete",
// req:         &BoshRequest{Payload: &BoshRequest_Start{Start: &StartBoshCapture{Token: "123d24", Deployment: "cf", Groups: []string{"router"}}}},
// wantErr:     true,
// expectedErr: errNilField,
// },

var (
	origin          = "pcap-api-1234ab"
	agentIdentifier = "router/123"
)

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

func (m *mockCaptureStream) Context() context.Context {
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
			captureStream:    &mockCaptureStream{nil, errorf(codes.Aborted, "unexpected error")},
			target:           AgentEndpoint{IP: "172.20.0.2"},
			contextCancelled: false,
			expectedData:     MessageType_INSTANCE_UNAVAILABLE,
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

			out := readMsgFromStream(ctx, tt.captureStream, tt.target, bufSize)

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

type mockRequestReceiver struct {
	req *CaptureRequest
	err error
	grpc.ServerStream
	context context.Context
}

func (m *mockRequestReceiver) Recv() (*CaptureRequest, error) {
	return m.req, m.err
}

func (m *mockRequestReceiver) Send(res *CaptureResponse) error {
	return nil
}

func (m *mockRequestReceiver) Context() context.Context {
	return m.context
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
			recv:        &mockRequestReceiver{req: nil, err: io.EOF},
			expectedErr: io.EOF,
			wantErr:     true,
		},
		{
			name:        "Empty payload",
			recv:        &mockRequestReceiver{req: &CaptureRequest{Operation: nil}, err: nil},
			expectedErr: errNilField,
			wantErr:     true,
		},
		{
			name:        "Empty message",
			recv:        &mockRequestReceiver{req: nil, err: nil},
			expectedErr: errNilField,
			wantErr:     true,
		},
		{
			name:        "Invalid payload type",
			recv:        &mockRequestReceiver{req: &CaptureRequest{Operation: &CaptureRequest_Start{Start: &StartCapture{Capture: &Capture{Capture: &Capture_Bosh{Bosh: &BoshCapture{}}}}}}, err: nil},
			expectedErr: errInvalidPayload,
			wantErr:     true,
		},
		{
			name:        "Happy path",
			recv:        &mockRequestReceiver{req: makeStopRequest(), err: nil},
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
			got := mergeResponseChannels(cs, bufSize)
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

type mockResponseSender struct {
}

func (m *mockResponseSender) Send(_ *CaptureResponse) error {
	return nil
}

func TestCapture(t *testing.T) {
	tests := []struct {
		name           string
		targets        []AgentEndpoint
		stream         captureReceiver
		err            error
		wantStatusCode codes.Code
		wantErr        bool
	}{
		{
			name:           "Capture cannot be started for all targets due to error",
			targets:        []AgentEndpoint{{"localhost", 8083, agentIdentifier}, {"localhost", 8084, "router/2abc"}},
			err:            errNilField,
			wantStatusCode: codes.FailedPrecondition,
			wantErr:        true,
		},
		{
			name:    "Test capture finished successfully with EOF",
			targets: []AgentEndpoint{{"localhost", 8083, agentIdentifier}, {"localhost", 8084, "router/2abc"}},
			stream:  &mockCaptureStream{nil, io.EOF},
			err:     nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zap.L()
			api, err := NewAPI(BufferConf{Size: 5, UpperLimit: 4, LowerLimit: 3}, AgentMTLS{MTLS: nil}, origin, 1)
			if err != nil {
				t.Errorf("capture() unexpected error during api creation: %v", err)
			}

			vcapIDKey := HeaderVcapID.String()

			ctx := metadata.NewOutgoingContext(context.Background(), metadata.MD{vcapIDKey: []string{"captureTest123"}})
			got, err := api.capture(ctx, &mockResponseSender{}, &CaptureOptions{}, tt.targets, log,
				func(ctx context.Context, req *CaptureOptions, target AgentEndpoint, creds credentials.TransportCredentials, log *zap.Logger) (captureReceiver, error) {
					return tt.stream, tt.err
				})
			if (err != nil) != tt.wantErr && status.Code(err) != tt.wantStatusCode {
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

func TestAPIStatus(t *testing.T) {
	tests := []struct {
		name       string
		draining   bool
		wantHealth bool
	}{
		{
			name:       "up and running",
			draining:   false,
			wantHealth: true,
		},
		{
			name:       "draining",
			draining:   true,
			wantHealth: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, err := NewAPI(BufferConf{Size: 5, UpperLimit: 4, LowerLimit: 3}, AgentMTLS{MTLS: nil}, origin, 1)
			if err != nil {
				t.Errorf("Status() unexpected error during api creation: %v", err)
			}

			if tt.draining {
				api.Stop()
			}
			got, err := api.Status(context.Background(), nil)
			if err != nil {
				t.Errorf("Status() unexpected error = %v", err)
			}
			if got.Healthy != tt.wantHealth {
				t.Errorf("Status() healthy = %v, wantHealth %v", got.Healthy, tt.wantHealth)
			}
		})
	}
}

func TestAPIRegisterHandler(t *testing.T) {
	tests := []struct {
		name              string
		handler           CaptureHandler
		wantRegistered    bool
		wantedHandlerName string
	}{
		{
			name:              "Register bosh handler and check the handler with correct name",
			handler:           &BoshHandler{Config: ManualEndpoints{Targets: []AgentEndpoint{{IP: "localhost", Port: 8083, Identifier: "test-agent/1"}}}},
			wantRegistered:    true,
			wantedHandlerName: "bosh",
		},
		{
			name:              "Register cf handler and check the handler with correct name",
			handler:           &CloudfoundryHandler{Config: ManualEndpoints{Targets: []AgentEndpoint{{IP: "localhost", Port: 8083, Identifier: "test-agent/1"}}}},
			wantRegistered:    true,
			wantedHandlerName: "cf",
		},
		{
			name:              "Register bosh handler and check the handler with invalid name",
			handler:           &BoshHandler{Config: ManualEndpoints{Targets: []AgentEndpoint{{IP: "localhost", Port: 8083, Identifier: "test-agent/1"}}}},
			wantRegistered:    false,
			wantedHandlerName: "cf",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, err := NewAPI(BufferConf{Size: 5, UpperLimit: 4, LowerLimit: 3}, AgentMTLS{MTLS: nil}, origin, 1)
			if err != nil {
				t.Errorf("RegisterHandler() unexpected error during api creation: %v", err)
			}

			api.RegisterHandler(tt.handler)
			registered := api.handlerRegistered(tt.wantedHandlerName)
			if registered != tt.wantRegistered {
				t.Errorf("RegisterHandler() expected registered %v but got: %v", tt.wantRegistered, registered)
			}
		})
	}
}

func TestAPICapture(t *testing.T) {
	tests := []struct {
		name           string
		stream         mockRequestReceiver
		apiRunning     bool
		wantErr        bool
		wantStatusCode codes.Code
	}{
		{
			name:           "API is draining",
			stream:         mockRequestReceiver{nil, nil, nil, context.Background()},
			apiRunning:     false,
			wantErr:        true,
			wantStatusCode: codes.Unavailable,
		},
		{
			name:           "Receiving of incoming request finished with error",
			stream:         mockRequestReceiver{nil, errNilField, nil, context.Background()},
			apiRunning:     true,
			wantErr:        true,
			wantStatusCode: codes.Unknown,
		},
		{
			name:           "Incoming Request is invalid",
			stream:         mockRequestReceiver{makeStopRequest(), nil, nil, context.Background()},
			apiRunning:     true,
			wantErr:        true,
			wantStatusCode: codes.InvalidArgument,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, err := NewAPI(BufferConf{Size: 5, UpperLimit: 4, LowerLimit: 3}, AgentMTLS{MTLS: nil}, origin, 1)
			if err != nil {
				t.Errorf("Capture() unexpected error during api creation: %v", err)
			}
			if !tt.apiRunning {
				api.Stop()
				time.Sleep(1 * time.Second)
			}

			err = api.Capture(&tt.stream)
			if (err != nil) != tt.wantErr {
				t.Errorf("Capture() error = %v, wantErr %v", err, tt.wantErr)
			}

			code := status.Code(err)
			if tt.wantErr && code != tt.wantStatusCode {
				t.Errorf("Capture() statusCode = %v, wantStatusCode = %v", code, tt.wantStatusCode)
			}
		})
	}
}
