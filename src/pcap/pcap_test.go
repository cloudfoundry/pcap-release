package pcap

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/google/gopacket"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/metadata"
	"io"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"testing"
)

func TestCaptureOptionsValidate(t *testing.T) {
	tests := []struct {
		name    string
		opts    *CaptureOptions
		wantErr bool
	}{
		{
			name:    "Error due to empty device name",
			opts:    &CaptureOptions{Filter: "host 10.0.0.1", SnapLen: 65000},
			wantErr: true,
		},
		{
			name:    "Error due to device name too long",
			opts:    &CaptureOptions{Device: randomDeviceNameFixedLength(17), Filter: "host 10.0.0.1", SnapLen: 65000},
			wantErr: true,
		},
		{
			name:    "Device name with valid length",
			opts:    &CaptureOptions{Device: randomDeviceNameFixedLength(16), Filter: "host 10.0.0.1", SnapLen: 65000},
			wantErr: false,
		},
		{
			name:    "Error due to invalid colon (:) in device name",
			opts:    &CaptureOptions{Device: "eth0:", Filter: "host 10.0.0.1", SnapLen: 65000},
			wantErr: true,
		},
		{
			name:    "Error due to invalid slash in device name",
			opts:    &CaptureOptions{Device: "eth0/", Filter: "host 10.0.0.1", SnapLen: 65000},
			wantErr: true,
		},
		{
			name:    "Error due to invalid char in device name",
			opts:    &CaptureOptions{Device: "\x00", Filter: "host 10.0.0.1", SnapLen: 65000},
			wantErr: true,
		},
		{
			name:    "Error due to invalid whitespace in device name",
			opts:    &CaptureOptions{Device: "eth0 -=", Filter: "host 10.0.0.1", SnapLen: 65000},
			wantErr: true,
		},
		{
			name:    "Error due to invalid device name",
			opts:    &CaptureOptions{Device: ".", Filter: "host 10.0.0.1", SnapLen: 65000},
			wantErr: true,
		},
		{
			name:    "Empty SnapLen",
			opts:    &CaptureOptions{Device: "eth0", Filter: "host 10.0.0.1", SnapLen: 0},
			wantErr: true,
		},
		{
			name:    "Very long filter",
			opts:    &CaptureOptions{Device: "eth0", Filter: generateFilterOptions(200), SnapLen: 65000},
			wantErr: true,
		},
		{
			name:    "Valid values",
			opts:    &CaptureOptions{Device: randomDeviceNameFixedLength(16), Filter: "host 10.0.0.1", SnapLen: 65000},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.opts.validate(); (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func randomDeviceNameFixedLength(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz0123456789-=")

	deviceName := make([]rune, n)
	for i := range deviceName {
		deviceName[i] = letters[rand.Intn(len(letters))]
	}
	return string(deviceName)
}

func generateFilterOptions(n int) string {
	var filter string
	filter = "host 10.0.0.1"
	for i := 2; i <= n; i++ {
		newFilterOptions := "host 10.0.0." + strconv.Itoa(i)
		filter = fmt.Sprintf("%s and %s and port 443", filter, newFilterOptions)
	}
	return filter
}
func TestBufferConfValidate(t *testing.T) {
	tests := []struct {
		name    string
		bc      BufferConf
		wantErr bool
	}{
		{
			name:    "Error due to buffer size negative",
			bc:      BufferConf{Size: -1},
			wantErr: true,
		},
		{
			name:    "Error due to upper limit greater than size",
			bc:      BufferConf{Size: 100, UpperLimit: 110, LowerLimit: 90},
			wantErr: true,
		},
		{
			name:    "Error due to lower limit greater than upper limit",
			bc:      BufferConf{Size: 100, UpperLimit: 95, LowerLimit: 98},
			wantErr: true,
		},
		{
			name:    "All values equals",
			bc:      BufferConf{Size: 100, UpperLimit: 100, LowerLimit: 100},
			wantErr: false,
		},
		{
			name:    "Lower limit equals upper limit",
			bc:      BufferConf{Size: 100, UpperLimit: 95, LowerLimit: 95},
			wantErr: false,
		},
		{
			name:    "Upper limit equals size",
			bc:      BufferConf{Size: 100, UpperLimit: 100, LowerLimit: 95},
			wantErr: false,
		},
		{
			name:    "All values zero",
			bc:      BufferConf{Size: 0, UpperLimit: 0, LowerLimit: 0},
			wantErr: false,
		},
		{
			name:    "Meaningful values",
			bc:      BufferConf{Size: 100, UpperLimit: 95, LowerLimit: 90},
			wantErr: false,
		},
	}
	validate := validator.New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validate.Struct(tt.bc); (err != nil) != tt.wantErr {
				t.Errorf("validate.Struct(BufferConfig) error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_generateApiFilter(t *testing.T) {
	tests := []struct {
		name           string
		interfaceAddrs func() ([]net.Addr, error)
		want           string
		wantErr        bool
	}{
		{
			"one ip address",
			func() ([]net.Addr, error) {
				return []net.Addr{&net.IPNet{
					IP:   net.IPv4(100, 100, 100, 100),
					Mask: nil,
				},
				}, nil
			},
			"ip host 100.100.100.100",
			false,
		},
		{
			"multiple ip addresses",
			func() ([]net.Addr, error) {
				return []net.Addr{
					&net.IPNet{
						IP:   net.IPv4(100, 100, 100, 100),
						Mask: nil,
					},
					&net.IPNet{
						IP:   net.IPv4(100, 100, 100, 101),
						Mask: nil,
					},
					&net.IPNet{
						IP:   net.IPv4(1, 100, 100, 100),
						Mask: nil,
					},
				}, nil
			},
			"ip host 100.100.100.100 or ip host 100.100.100.101 or ip host 1.100.100.100",
			false,
		},
		{
			"no ip address",
			func() ([]net.Addr, error) {
				return []net.Addr{}, nil
			},
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interfaceAddrs = tt.interfaceAddrs
			got, err := generateAPIFilter()
			if (err != nil) != tt.wantErr {
				t.Errorf("generateApiFilter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("generateApiFilter() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_patchFilter(t *testing.T) {
	tests := []struct {
		name           string
		filter         string
		interfaceAddrs func() ([]net.Addr, error)
		want           string
		wantErr        bool
	}{
		{
			"simple filter",
			"port 443",
			func() ([]net.Addr, error) {
				return []net.Addr{
					&net.IPNet{
						IP:   net.IPv4(100, 100, 100, 100),
						Mask: nil,
					},
					&net.IPNet{
						IP:   net.IPv4(100, 100, 100, 101),
						Mask: nil,
					},
					&net.IPNet{
						IP:   net.IPv4(1, 100, 100, 100),
						Mask: nil,
					},
				}, nil
			},
			"not (ip host 100.100.100.100 or ip host 100.100.100.101 or ip host 1.100.100.100) and (port 443)",
			false,
		},
		{
			"no filter",
			"",
			func() ([]net.Addr, error) {
				return []net.Addr{
					&net.IPNet{
						IP:   net.IPv4(100, 100, 100, 100),
						Mask: nil,
					},
				}, nil
			},
			"not (ip host 100.100.100.100)",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interfaceAddrs = tt.interfaceAddrs
			got, err := patchFilter(tt.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("patchFilter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("patchFilter() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_containsForbiddenRunes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{
			"valid string",
			"port 443",
			false,
		},
		{
			"valid string with complex expression",
			"(port 443) and ip host 10.0.0.1 or (ether proto \\ip and tcp)",
			false,
		},
		{
			"illegal character",
			"port 443\v",
			true,
		},
		{
			"empty string",
			"",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsForbiddenRunes(tt.in); got != tt.want {
				t.Errorf("containsForbiddenRunes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetVcapId(t *testing.T) {
	tests := []struct {
		name           string
		md             metadata.MD
		externalVcapID string
		vcapID         string
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
			md:     metadata.MD{HeaderVcapID.String(): []string{"123"}},
			vcapID: "123",
		},
		{
			name:           "Metadata with external vcap request id",
			externalVcapID: "external123",
			vcapID:         "external123",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), tt.md)

			observedZapCore, observedLogs := observer.New(zap.InfoLevel)
			log := zap.New(observedZapCore)

			externalVcapID := &tt.externalVcapID
			if tt.externalVcapID == "" {
				externalVcapID = nil
			}
			ctx, log = setVcapID(ctx, log, externalVcapID)
			// ensure that at least one log has been observed
			log.Info("test")

			got := ctx.Value(HeaderVcapID)
			if got == nil {
				t.Fatal("missing vcapID")
			}

			vcapID := fmt.Sprint(got)

			if vcapID != "" && tt.vcapID != "" && vcapID != tt.vcapID {
				t.Errorf("expected %s but got %s", tt.vcapID, vcapID)
			}

			checkLogsContainExpectedField(t, observedLogs, tt.vcapID, LogKeyVcapID)
		})
	}
}

func checkLogsContainExpectedField(t *testing.T, observedLogs *observer.ObservedLogs, vcapID string, expectedLogField string) {
	t.Helper()

	if observedLogs == nil || observedLogs.Len() == 0 {
		t.Fatal("No logs are written")
	}

	entry := observedLogs.All()[observedLogs.Len()-1]

	for _, logField := range entry.Context {
		if logField.Key == expectedLogField && (vcapID == "" || logField.String == vcapID) {
			return
		}
	}

	t.Errorf("missing field %s or field has wrong value", expectedLogField)
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
			response:    newPacketResponse([]byte("ABC"), gopacket.CaptureInfo{}),
			expectedErr: io.EOF,
		},
		{
			name:        "buffer is filled with PacketResponse, one packet discarded",
			stream:      &mockPacketSender{err: nil, sentRes: bufUpperLimit + 1},
			resToBeSent: bufUpperLimit + 2,
			response:    newPacketResponse([]byte("ABC"), gopacket.CaptureInfo{}),
			expectedErr: errTestEnded,
		},
		{
			name:        "buffer is filled with MessageResponse, no packets discarded",
			stream:      &mockPacketSender{err: nil, sentRes: bufUpperLimit + 1},
			resToBeSent: bufUpperLimit + 1,
			response:    newMessageResponse(MessageType_INSTANCE_UNAVAILABLE, "invalid id", agentOrigin),
			expectedErr: errTestEnded,
		},
		{
			name:        "buffer is filled with PacketResponse, discarding packets",
			stream:      &mockPacketSender{err: nil, stopAfterErrorOccurs: true},
			resToBeSent: bufUpperLimit + 1,
			response:    newPacketResponse([]byte("ABC"), gopacket.CaptureInfo{}),
			expectedErr: errDiscardedMsg,
		},
		{
			name:        "happy path",
			stream:      &mockPacketSender{err: nil, sentRes: bufUpperLimit - 1},
			resToBeSent: bufUpperLimit - 1,
			response:    newPacketResponse([]byte("ABC"), gopacket.CaptureInfo{}),
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

			forwardToStream(cancel, src, test.stream, BufferConf{Size: 5, UpperLimit: 4, LowerLimit: 3}, wg, agentOrigin)

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
