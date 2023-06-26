package main

import (
	"encoding/json"
	"encoding/pem"
	"github.com/cloudfoundry/pcap-release/src/pcap"
	"net/http"
	"net/http/httptest"
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
			name:    "invalid - different schema -ftp",
			url:     "ftp://google.com",
			wantErr: true,
		}, {
			name:    "invalid - different schema -httpx",
			url:     "httpx://google.com",
			wantErr: true,
		}, {
			name:    "invalid - different schema - special chars",
			url:     "h_+.x://google.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := urlWithScheme(tt.url)
			parsedURL, err := parseAPIURL(url)
			if (err != nil) != tt.wantErr {
				t.Errorf("%s: wantErr = %t, gotError = %v", tt.url, tt.wantErr, err)
			}
			if tt.expectedScheme != "" && parsedURL.Scheme != tt.expectedScheme {
				t.Errorf("expectedScheme = %v, actual = %v", tt.expectedScheme, parsedURL.Scheme)
			}
		})
	}
}

func TestEnvironment_Connect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/info", func(writer http.ResponseWriter, request *http.Request) {
		info := pcap.BoshInfo{}
		info.UserAuthentication.Options.URL = "https://uaa.fakebosh.com"

		_ = json.NewEncoder(writer).Encode(info)
	})

	fakeBosh := httptest.NewTLSServer(mux)
	defer fakeBosh.Close()

	fakeBoshNoTLS := httptest.NewServer(mux)
	defer fakeBoshNoTLS.Close()

	tests := []struct {
		name    string
		url     string
		cacert  string
		wantErr bool
	}{
		{
			name:    "valid - TLS Full URL with CaCert",
			url:     fakeBosh.URL,
			cacert:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fakeBosh.Certificate().Raw})),
			wantErr: false,
		},
		{
			name:    "valid - TLS IP only with CaCert",
			url:     fakeBosh.Listener.Addr().String(),
			cacert:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fakeBosh.Certificate().Raw})),
			wantErr: false,
		},
		{
			name:    "invalid - TLS Full URL without CaCert",
			url:     fakeBosh.URL,
			cacert:  "",
			wantErr: true,
		},
		{
			name:    "invalid - TLS IP only without CaCert",
			url:     fakeBosh.Listener.Addr().String(),
			cacert:  "",
			wantErr: true,
		},
		{
			name:    "valid - No TLS Full URL with CaCert",
			url:     fakeBoshNoTLS.URL,
			cacert:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fakeBosh.Certificate().Raw})),
			wantErr: false,
		},
		{
			name:    "valid - No TLS Full URL without CaCert",
			url:     fakeBoshNoTLS.URL,
			cacert:  "",
			wantErr: false,
		},
		{
			name:    "invalid - No TLS IP only with CaCert",
			url:     fakeBoshNoTLS.Listener.Addr().String(),
			cacert:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fakeBosh.Certificate().Raw})),
			wantErr: true,
		},
		{
			name:    "invalid - No TLS IP only without CaCert",
			url:     fakeBoshNoTLS.Listener.Addr().String(),
			cacert:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			environment := Environment{
				URL:    tt.url,
				CaCert: tt.cacert,
			}
			err := environment.connect()
			if (err != nil) != tt.wantErr {
				t.Errorf("%s: wantErr = %t, gotError = %v", tt.url, tt.wantErr, err)
			}
		})
	}
}
