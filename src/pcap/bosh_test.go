package pcap

import (
	"errors"
	"testing"
)

func TestValidateBoshCaptureRequest(t *testing.T) {
	tests := []struct {
		name        string
		req         *BoshQuery
		wantErr     bool
		expectedErr error
	}{
		{
			name:        "Bosh metadata is nil",
			req:         nil,
			wantErr:     true,
			expectedErr: errNilField,
		},
		{
			name:        "Bosh metadata is empty",
			req:         &BoshQuery{},
			wantErr:     true,
			expectedErr: errEmptyField,
		},

		{
			name:        "Bosh metadata Token is not present",
			req:         &BoshQuery{Deployment: "cf", Groups: []string{"router"}},
			wantErr:     true,
			expectedErr: errEmptyField,
		},
		{
			name:        "Bosh metadata Deployment field is not present",
			req:         &BoshQuery{Token: "123d24", Groups: []string{"router"}},
			wantErr:     true,
			expectedErr: errEmptyField,
		},
		{
			name:        "Bosh metadata Groups field is not present",
			req:         &BoshQuery{Token: "123d24", Deployment: "cf"},
			wantErr:     true,
			expectedErr: errEmptyField,
		},
		{
			name:        "Valid request",
			req:         &BoshQuery{Token: "123d24", Deployment: "cf", Groups: []string{"router"}},
			wantErr:     false,
			expectedErr: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bosh := &BoshHandler{}

			testCapture := &AgentEndpoints{Capture: &Capture_Bosh{test.req}}

			err := bosh.validate(testCapture)
			if (err != nil) != test.wantErr {
				t.Errorf("wantErr = %v, error = %v", test.wantErr, err)
			}
			if test.expectedErr != nil && !errors.Is(err, test.expectedErr) {
				t.Errorf("expectedErr = %v, error = %v", test.expectedErr, err)
			}
		})
	}
}
