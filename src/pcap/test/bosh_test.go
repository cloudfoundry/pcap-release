package test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/cloudfoundry/pcap-release/src/pcap/test/mock"

	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
)

var (
	origin = "pcap-api-1234ab"
)

func TestNewBoshResolver(t *testing.T) {
	jwtapi, _ := mock.NewMockJWTAPI()
	boshAPI := mock.NewMockBoshDirectorAPI(nil, jwtapi.URL)

	tests := []struct {
		name          string
		apiBoshConfig pcap.BoshResolverConfig
		wantErr       bool
		expectedErr   error
	}{
		{
			name: "validEnvironment",
			apiBoshConfig: pcap.BoshResolverConfig{
				RawDirectorURL: boshAPI.URL,
				AgentPort:      8083,
			},
			wantErr: false,
		},
		{
			name: "empty Bosh Director URL",
			apiBoshConfig: pcap.BoshResolverConfig{
				RawDirectorURL: "",
				AgentPort:      0,
			},
			wantErr:     true,
			expectedErr: nil,
		},
		{
			name: "unreacheable Bosh Director",
			apiBoshConfig: pcap.BoshResolverConfig{
				RawDirectorURL: "localhost:60000",
				AgentPort:      0,
			},
			wantErr:     true,
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			boshResolver, err := pcap.NewBoshResolver(tt.apiBoshConfig)
			if err != nil {
				if (err != nil) != tt.wantErr {
					t.Errorf("wantErr = %v, error = %v", tt.wantErr, err)
				}
				if tt.expectedErr != nil && !errors.Is(err, tt.expectedErr) {
					t.Errorf("expectedErr = %v, actualErr = %v", tt.expectedErr, err)
				}
			} else if boshResolver == nil {
				t.Error("boshResolver is nil")
			}
		})
	}
}

func TestAuthenticate(t *testing.T) {
	bar, _, _, err := mock.NewResolverWithMockBoshAPI(nil)
	if err != nil {
		t.Errorf(err.Error())
	}

	validToken, err := mock.GetValidToken(bar.UaaURLs[0])
	if err != nil {
		t.Errorf("failed to get valid token")
	}

	tests := []struct {
		name        string
		token       string
		wantErr     bool
		expectedErr error
	}{
		{
			name:        "valid token",
			token:       validToken,
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name:        "invalid token - mismatching jku",
			token:       "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vMTAuMC4zLjExOjg0NDMvdG9rZW5fa2V5cyIsImtpZCI6InVhYS1qd3Qta2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiIwZWNmODIxYjVmYzI0YTBmODczOWM5MmJkOGY2YzYyMi1yIiwic3ViIjoiMDY4ZmEwODItMDdkNy00NjRjLWE1MWEtZmFkMzdiNGQ2MDViIiwiaWF0IjoxNjc3NTM0Mjg3LCJleHAiOjE2Nzc2MjA2ODcsImNpZCI6ImJvc2hfY2xpIiwiY2xpZW50X2lkIjoiYm9zaF9jbGkiLCJpc3MiOiJodHRwczovLzEwLjAuMy4xMTo4NDQzL29hdXRoL3Rva2VuIiwiemlkIjoidWFhIiwiYXVkIjpbIm9wZW5pZCIsImJvc2hfY2xpIiwiYm9zaCJdLCJncmFudGVkX3Njb3BlcyI6WyJvcGVuaWQiLCJib3NoLmFkbWluIl0sImFtciI6WyJwd2QiXSwiYXV0aF90aW1lIjoxNjc3NTM0Mjg3LCJncmFudF90eXBlIjoicGFzc3dvcmQiLCJ1c2VyX25hbWUiOiJoLmk1NTQwNzYuOTFiNjc1Iiwib3JpZ2luIjoidWFhIiwidXNlcl9pZCI6IjA2OGZhMDgyLTA3ZDctNDY0Yy1hNTFhLWZhZDM3YjRkNjA1YiIsInJldl9zaWciOiJjMGRkMTY0MSJ9.o7t1HSihRZNrHKeCynj5K8xM5EixOMr33F37N7i2Zy-I2d8T9LLXCbY9nczQboSG2UtDFu-ztr7xMFwpsCYzVgGItWPBMY62tk4GVir1zFYEDChFXF6vaL3Lv9Y1L9AOwtT6Nr47jYY5XxkLmVgjfXb2wDx7lL8OG0BvVmKrQDtZuUlYhyXQNDkhBHQlXh5TqK07LgPzOoWgoVcNGNlpjj3hOnHNAq-gexNqJHtIBJ-0AdcadyE3wrKWCxeuQGkEnnMG3M2ByVoFd6_V2UnizxCnIpaoVOLJqywUyxOecmALLg4c9M6Bymkv5oR_CgbMGcVTxocwGgDYXVZ20TpbOg",
			wantErr:     true,
			expectedErr: pcap.ErrNotAuthorized,
		},
		{
			name:        "invalid token - not a token",
			token:       "notatoken",
			wantErr:     true,
			expectedErr: jwt.ErrTokenMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err = bar.Authenticate(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("wantErr = %v, error = %v", tt.wantErr, err)
			}
			if tt.expectedErr != nil && !errors.Is(err, tt.expectedErr) {
				t.Errorf("expectedErr = %v,\n\t\t\t\t\t\t\t   actualErr = %v", tt.expectedErr, err)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	log := zap.L() // TODO: Proper log handling?
	deploymentName := "test-deployment"

	expectedAgentEndpoints := []pcap.AgentEndpoint{
		{
			IP:         "192.168.0.1",
			Port:       8083,
			Identifier: "test-instance-group/Testagent1",
		},
		{
			IP:         "192.168.0.2",
			Port:       8083,
			Identifier: "test-instance-group/Testagent2",
		},
	}

	boshResolver, _, _, err := mock.NewDefaultResolverWithMockBoshAPIWithEndpoints(expectedAgentEndpoints, deploymentName)
	if err != nil {
		t.Errorf("received unexpected error = %v", err)
	}

	validToken, err := mock.GetValidToken(boshResolver.UaaURLs[0])
	if err != nil {
		t.Error(err)
	}

	request := &pcap.EndpointRequest{
		Request: &pcap.EndpointRequest_Bosh{
			Bosh: &pcap.BoshRequest{
				Token:      validToken,
				Deployment: deploymentName,
				Groups:     []string{"test-instance-group"},
				Instances:  nil,
			},
		},
	}

	agentEndpoints, err := boshResolver.Resolve(request, log)
	if err != nil {
		t.Errorf("received unexpected error = %v", err)
	}

	if !reflect.DeepEqual(expectedAgentEndpoints, agentEndpoints) {
		t.Errorf("endpoint mismatch: expected = %v, actual = %v", expectedAgentEndpoints, agentEndpoints)
	}
}

func TestCanResolveEndpointRequest(t *testing.T) {
	tests := []struct {
		name           string
		req            *pcap.EndpointRequest
		expectedResult bool
	}{
		{
			name: "BoshRequest",
			req: &pcap.EndpointRequest{
				Request: &pcap.EndpointRequest_Bosh{
					Bosh: &pcap.BoshRequest{},
				},
			},
			expectedResult: true,
		},
		{
			name: "CFRequest",
			req: &pcap.EndpointRequest{
				Request: &pcap.EndpointRequest_Cf{
					Cf: &pcap.CloudfoundryRequest{},
				},
			},
			expectedResult: false,
		},
	}

	boshResolver, _, _, err := mock.NewResolverWithMockBoshAPI(nil) // NewBoshResolver(bosh.Environment{}, 8083)
	if err != nil {
		t.Error(err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := boshResolver.CanResolve(tt.req)
			if tt.expectedResult != result {
				t.Errorf("expectedResult = %v, result = %v", tt.expectedResult, result)
			}
		})
	}
}

func TestValidateBoshEndpointRequest(t *testing.T) {
	tests := []struct {
		name        string
		req         *pcap.BoshRequest
		wantErr     bool
		expectedErr error
	}{
		{
			name:    "Bosh metadata is nil",
			req:     nil,
			wantErr: true,
			//expectedErr: errNilField,
		},
		{
			name:    "Bosh metadata is empty",
			req:     &pcap.BoshRequest{},
			wantErr: true,
			//expectedErr: errEmptyField,
		},

		{
			name:    "Bosh metadata Token is not present",
			req:     &pcap.BoshRequest{Deployment: "cf", Groups: []string{"router"}},
			wantErr: true,
			//expectedErr: errEmptyField,
		},
		{
			name:    "Bosh metadata Deployment field is not present",
			req:     &pcap.BoshRequest{Token: "123d24", Groups: []string{"router"}},
			wantErr: true,
			//expectedErr: errEmptyField,
		},
		{
			name:    "Bosh metadata Groups field is not present",
			req:     &pcap.BoshRequest{Token: "123d24", Deployment: "cf"},
			wantErr: true,
			//expectedErr: errEmptyField,
		},
		{
			name: "Valid request",
			req: &pcap.BoshRequest{
				Token: "123d24", Deployment: "cf", Groups: []string{"router"},
			},
			wantErr:     false,
			expectedErr: nil,
		},
	}

	boshResolver, _, _, err := mock.NewResolverWithMockBoshAPI(nil) // NewBoshResolver(bosh.Environment{}, 8083)
	if err != nil {
		t.Error(err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testEndpointRequest := &pcap.EndpointRequest{Request: &pcap.EndpointRequest_Bosh{Bosh: tt.req}}

			err = boshResolver.Validate(testEndpointRequest)
			if (err != nil) != tt.wantErr {
				t.Errorf("wantErr = %v, error = %v", tt.wantErr, err)
			}
			if tt.expectedErr != nil && !errors.Is(err, tt.expectedErr) {
				t.Errorf("expectedErr = %v, error = %v", tt.expectedErr, err)
			}
		})
	}
}

func TestAPIRegisterHandler(t *testing.T) {
	jwtapi, _ := mock.NewMockJWTAPI()
	boshAPI := mock.NewMockBoshDirectorAPI(nil, jwtapi.URL)

	config := pcap.BoshResolverConfig{
		RawDirectorURL: boshAPI.URL,
		MTLS:           nil,
		AgentPort:      8083,
	}
	boshResolver, err := pcap.NewBoshResolver(config)
	if err != nil {
		panic(err)
	}

	tests := []struct {
		name               string
		resolver           pcap.AgentResolver
		wantRegistered     bool
		wantedResolverName string
	}{
		{
			name:               "Register bosh handler and check the handler with correct name",
			resolver:           boshResolver,
			wantRegistered:     true,
			wantedResolverName: pcap.BoshResolverName,
		},
		{
			name:               "Register bosh handler and check the handler with invalid name",
			resolver:           boshResolver,
			wantRegistered:     false,
			wantedResolverName: "cf",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var api *pcap.API
			api, err = pcap.NewAPI(pcap.BufferConf{Size: 5, UpperLimit: 4, LowerLimit: 3}, nil, origin, 1)
			if err != nil {
				t.Errorf("RegisterResolver() unexpected error during api creation: %v", err)
			}

			api.RegisterResolver(tt.resolver)
			registered := api.HasResolver(tt.wantedResolverName)
			if registered != tt.wantRegistered {
				t.Errorf("RegisterResolver() expected registered %v but got %v", tt.wantRegistered, registered)
			}
		})
	}
}
