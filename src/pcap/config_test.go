package pcap

import (
	"crypto/x509"
	"testing"
)

func TestCreateCAPool(t *testing.T) {
	tests := []struct {
		name     string
		certFile string
		wantErr  bool
	}{
		{
			name:     "validCA",
			certFile: "test/testcerts/valid_with_empty_lines.crt",
			wantErr:  false,
		}, {
			name:     "garbage CA",
			certFile: "test/testcerts/invalid.crt",
			wantErr:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			caPool, err := createCAPool(test.certFile)
			if (err != nil) != test.wantErr {
				t.Errorf("wantErr = %v, error = %v", test.wantErr, err)
			}
			if err == nil && caPool.Equal(x509.NewCertPool()) {
				t.Errorf("expected non-empty caPool")
			}
		})
	}
}
