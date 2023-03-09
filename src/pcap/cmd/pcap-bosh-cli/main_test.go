package main

import (
	"testing"
)

func TestParseAPIURL(t *testing.T) {

	tests := []struct {
		name           string
		url            string
		wantErr        bool
		expectedScheme string
	}{
		{
			name:           "valid - w/o schema",
			url:            "localhost:8080",
			wantErr:        false,
			expectedScheme: "https",
		}, {
			name:           "valid - https://",
			url:            "https://localhost:8080",
			wantErr:        false,
			expectedScheme: "https",
		}, {
			name:           "valid - http",
			url:            "http://localhost:8080",
			wantErr:        false,
			expectedScheme: "http",
		}, {
			name:    "invalid - different schema",
			url:     "ftp://google.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		parsedURL, err := parseAPIURL(tt.url)
		if (err != nil) != tt.wantErr {
			t.Errorf("%s: wantErr = %t, gotError = %v", tt.url, tt.wantErr, err)
		}
		if tt.expectedScheme != "" && parsedURL.Scheme != tt.expectedScheme {
			t.Errorf("expectedScheme = %v, actual = %v", tt.expectedScheme, parsedURL.Scheme)
		}
	}
}
