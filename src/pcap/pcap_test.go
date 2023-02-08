package pcap

import (
	"math/rand"
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