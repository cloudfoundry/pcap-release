package pcap

import (
	"testing"
)

func TestCaptureOptions_validate(t *testing.T) {
	tests := []struct {
		name    string
		opts    *CaptureOptions
		wantErr bool
	}{
		{
			name:    "Empty device name",
			opts:    &CaptureOptions{Filter: "host 10.0.0.1", SnapLen: 65000},
			wantErr: true,
		},
		{
			name:    "Invalid device name",
			opts:    &CaptureOptions{Device: "eth0-=", Filter: "host 10.0.0.1", SnapLen: 65000},
			wantErr: true,
		},
		{
			name:    "Empty SnapLen",
			opts:    &CaptureOptions{Device: "eth0", Filter: "host 10.0.0.1", SnapLen: 0},
			wantErr: true,
		},
		{
			name:    "Valid values ",
			opts:    &CaptureOptions{Device: "eth0", Filter: "host 10.0.0.1", SnapLen: 65000},
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

func TestBufferConf_validate(t *testing.T) {
	tests := []struct {
		name    string
		bc      BufferConf
		wantErr bool
	}{
		{
			name:    "Size negative",
			bc:      BufferConf{Size: -1},
			wantErr: true,
		},
		{
			name:    "Upper limit greater than size",
			bc:      BufferConf{Size: 100, UpperLimit: 110, LowerLimit: 90},
			wantErr: true,
		},
		{
			name:    "Lower limit greater than upper limit",
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
			name:    "Valid values",
			bc:      BufferConf{Size: 100, UpperLimit: 95, LowerLimit: 90},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.bc.validate(); (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
