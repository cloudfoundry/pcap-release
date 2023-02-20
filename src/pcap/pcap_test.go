package pcap

import (
	"context"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/metadata"
	"math/rand"
	"net"
	"strconv"
	"testing"

	"github.com/go-playground/validator/v10"
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
		externalVcapId string
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
			md:     metadata.MD{HeaderVcapID: []string{"123"}},
			vcapID: "123",
		},
		{
			name:           "Metadata with vcap request id",
			externalVcapId: "external123",
			vcapID:         "external123",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), tt.md)

			observedZapCore, observedLogs := observer.New(zap.InfoLevel)
			log := zap.New(observedZapCore)

			ctx, log = setVcapID(ctx, log, &tt.externalVcapId)

			got, ok := metadata.FromOutgoingContext(ctx)
			if !ok {
				t.Fatal("missing outgoing context")
			}

			vcapID, _ := getVcapFromMD(got)
			if vcapID != nil && tt.vcapID != "" && *vcapID != tt.vcapID {
				t.Errorf("expected %s but got %s", tt.vcapID, *vcapID)
			}

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

func Test_vcapIDFromOutgoingCtx(t *testing.T) {
	tests := []struct {
		name    string
		md      metadata.MD
		want    string
		wantErr error
	}{
		{
			name:    "no metadata",
			md:      nil,
			wantErr: errNoMetadata,
		},
		{
			name:    "metadata without vcap-id",
			md:      metadata.MD{},
			wantErr: errNoVcapID,
		},
		{
			name: "metadata with vcap-id",
			md:   metadata.MD{HeaderVcapID: []string{"123"}},
			want: "123",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.md != nil {
				ctx = metadata.NewOutgoingContext(ctx, tt.md)
			}
			got, err := vcapIDFromOutgoingCtx(ctx)
			if err != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("vcapIDFromOutgoingCtx() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil && tt.want != "" && *got != tt.want {
				t.Errorf("vcapIDFromOutgoingCtx() got = %v, want %v", got, tt.want)
			}
		})
	}
}
