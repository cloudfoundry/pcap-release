package pcap

import (
	"errors"
	"testing"
)

func TestValidateCfCaptureRequest(t *testing.T) {
	tests := []struct {
		name        string
		req         *CloudfoundryRequest
		wantErr     bool
		expectedErr error
	}{
		{
			name:        "CF metadata is nil",
			req:         nil,
			wantErr:     true,
			expectedErr: errNilField,
		},
		{
			name:        "CF metadata is empty",
			req:         &CloudfoundryRequest{},
			wantErr:     true,
			expectedErr: errEmptyField,
		},

		{
			name:        "CF metadata Token is not present",
			req:         &CloudfoundryRequest{AppId: "123abc"},
			wantErr:     true,
			expectedErr: errEmptyField,
		},
		{
			name:        "CF metadata Deployment field is not present",
			req:         &CloudfoundryRequest{Token: "123d24"},
			wantErr:     true,
			expectedErr: errEmptyField,
		},
		{
			name:        "Valid request",
			req:         &CloudfoundryRequest{Token: "123d24", AppId: "123abc"},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name:        "Valid request with instances",
			req:         &CloudfoundryRequest{Token: "123d24", AppId: "123abc", Indices: []int32{1, 3, 5}},
			wantErr:     false,
			expectedErr: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cf := &CloudfoundryAgentResolver{}

			testCapture := &EndpointRequest{Request: &EndpointRequest_Cf{test.req}}

			err := cf.validate(testCapture)
			if (err != nil) != test.wantErr {
				t.Errorf("wantErr = %v, error = %v", test.wantErr, err)
			}
			if test.expectedErr != nil && !errors.Is(err, test.expectedErr) {
				t.Errorf("expectedErr = %v, error = %v", test.expectedErr, err)
			}
		})
	}
}
