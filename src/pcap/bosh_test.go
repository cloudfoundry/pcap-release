package pcap

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/cloudfoundry/pcap-release/src/pcap/test"
)

func NewResolverWithMockBoshAPI(responses map[string]string) (*BoshResolver, error) {
	jwtapi, _ := test.MockJWTAPI()
	boshAPI := test.MockBoshDirectorAPI(responses, jwtapi.URL)
	config := BoshResolverConfig{
		RawDirectorURL:   boshAPI.URL,
		EnvironmentAlias: "bosh",
		AgentPort:        8083,
		TokenScope:       "bosh.admin", // TODO Test for other scopes?
	}
	boshResolver, err := NewBoshResolver(config)
	if err != nil {
		return nil, err
	}
	boshResolver.uaaURLs = []string{jwtapi.URL}
	return boshResolver, nil
}

func TestNewBoshResolver(t *testing.T) {
	jwtapi, _ := test.MockJWTAPI()
	boshAPI := test.MockBoshDirectorAPI(nil, jwtapi.URL)

	tests := []struct {
		name          string
		apiBoshConfig BoshResolverConfig
		wantErr       bool
		expectedErr   error
	}{
		{
			name: "validEnvironment",
			apiBoshConfig: BoshResolverConfig{
				EnvironmentAlias: "bosh",
				RawDirectorURL:   boshAPI.URL,
				AgentPort:        8083,
			},
			wantErr: false,
		},
		{
			name: "empty Bosh Director URL",
			apiBoshConfig: BoshResolverConfig{
				EnvironmentAlias: "",
				RawDirectorURL:   "",
				AgentPort:        0,
			},
			wantErr:     true,
			expectedErr: nil,
		},
		{
			name: "unreacheable Bosh Director",
			apiBoshConfig: BoshResolverConfig{
				EnvironmentAlias: "",
				RawDirectorURL:   "localhost:60000",
				AgentPort:        0,
			},
			wantErr:     true,
			expectedErr: nil,
		},
		// TODO: test for MTLS
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			boshResolver, err := NewBoshResolver(tt.apiBoshConfig)
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
	bar, err := NewResolverWithMockBoshAPI(nil)
	if err != nil {
		t.Errorf(err.Error())
	}

	validToken, err := test.GetValidToken(bar.uaaURLs[0])
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
			expectedErr: nil, // TODO: custom error comparison currently not implemented, see wrap.go:53
			// expectedErr: fmt.Errorf("could not verify token eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vMTAuMC4zLjExOjg0NDMvdG9rZW5fa2V5cyIsImtpZCI6InVhYS1qd3Qta2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiIwZWNmODIxYjVmYzI0YTBmODczOWM5MmJkOGY2YzYyMi1yIiwic3ViIjoiMDY4ZmEwODItMDdkNy00NjRjLWE1MWEtZmFkMzdiNGQ2MDViIiwiaWF0IjoxNjc3NTM0Mjg3LCJleHAiOjE2Nzc2MjA2ODcsImNpZCI6ImJvc2hfY2xpIiwiY2xpZW50X2lkIjoiYm9zaF9jbGkiLCJpc3MiOiJodHRwczovLzEwLjAuMy4xMTo4NDQzL29hdXRoL3Rva2VuIiwiemlkIjoidWFhIiwiYXVkIjpbIm9wZW5pZCIsImJvc2hfY2xpIiwiYm9zaCJdLCJncmFudGVkX3Njb3BlcyI6WyJvcGVuaWQiLCJib3NoLmFkbWluIl0sImFtciI6WyJwd2QiXSwiYXV0aF90aW1lIjoxNjc3NTM0Mjg3LCJncmFudF90eXBlIjoicGFzc3dvcmQiLCJ1c2VyX25hbWUiOiJoLmk1NTQwNzYuOTFiNjc1Iiwib3JpZ2luIjoidWFhIiwidXNlcl9pZCI6IjA2OGZhMDgyLTA3ZDctNDY0Yy1hNTFhLWZhZDM3YjRkNjA1YiIsInJldl9zaWciOiJjMGRkMTY0MSJ9.o7t1HSihRZNrHKeCynj5K8xM5EixOMr33F37N7i2Zy-I2d8T9LLXCbY9nczQboSG2UtDFu-ztr7xMFwpsCYzVgGItWPBMY62tk4GVir1zFYEDChFXF6vaL3Lv9Y1L9AOwtT6Nr47jYY5XxkLmVgjfXb2wDx7lL8OG0BvVmKrQDtZuUlYhyXQNDkhBHQlXh5TqK07LgPzOoWgoVcNGNlpjj3hOnHNAq-gexNqJHtIBJ-0AdcadyE3wrKWCxeuQGkEnnMG3M2ByVoFd6_V2UnizxCnIpaoVOLJqywUyxOecmALLg4c9M6Bymkv5oR_CgbMGcVTxocwGgDYXVZ20TpbOg (header 'jku' https://10.0.3.11:8443/token_keys did not match any UAA base URLs reported by the BOSH Director: [%v])", bar.uaaURLs[0]),
		},
		{
			name:        "invalid token - not a token",
			token:       "notatoken",
			wantErr:     true,
			expectedErr: nil, // TODO: custom error comparison currently not implemented, see wrap.go:53
			// expectedErr: fmt.Errorf("could not verify token notatoken (token contains an invalid number of segments)"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err = bar.authenticate(tt.token)
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

	expectedAgentEndpoints := []AgentEndpoint{
		{
			IP:         "192.168.0.1",
			Port:       8083,
			Identifier: "ha_proxy_z1/Testagent1",
		},
		{
			IP:         "192.168.0.2",
			Port:       8083,
			Identifier: "ha_proxy_z1/Testagent2",
		},
	}

	var haproxyInstances []BoshInstance

	timeString := "2022-09-26T21:28:39Z"
	timestamp, _ := time.Parse(time.RFC3339, timeString)
	for _, endpoint := range expectedAgentEndpoints {
		parts := strings.Split(endpoint.Identifier, "/")
		job, id := parts[0], parts[1]

		instance := BoshInstance{
			AgentID:     endpoint.Identifier,
			Cid:         "agent_id:a9c3cda6-9cd9-457f-aad4-143405bf69db;resource_group_name:rg-azure-cfn01",
			Job:         job,
			Index:       0,
			ID:          id,
			Az:          "z1",
			Ips:         []string{endpoint.IP},
			VMCreatedAt: timestamp,
			ExpectsVM:   true,
		}
		haproxyInstances = append(haproxyInstances, instance)
	}

	instances, err := json.Marshal(haproxyInstances)
	if err != nil {
		panic(err)
	}

	responses := map[string]string{
		fmt.Sprintf("/deployments/%v/instances", deploymentName): string(instances),
	}

	boshResolver, err := NewResolverWithMockBoshAPI(responses)
	if err != nil {
		t.Errorf("received unexpected error = %v", err)
	}

	validToken, err := test.GetValidToken(boshResolver.uaaURLs[0])
	if err != nil {
		t.Error(err)
	}

	request := &EndpointRequest{
		Request: &EndpointRequest_Bosh{
			Bosh: &BoshRequest{
				Token:       validToken,
				Deployment:  deploymentName,
				Groups:      []string{"test-instance-group"},
				Instances:   nil,
				Environment: "bosh/bosh",
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
		req            *EndpointRequest
		expectedResult bool
	}{
		{
			name: "BoshRequest",
			req: &EndpointRequest{
				Request: &EndpointRequest_Bosh{
					Bosh: &BoshRequest{Environment: "bosh"},
				},
			},
			expectedResult: true,
		},
		{
			name: "CFRequest",
			req: &EndpointRequest{
				Request: &EndpointRequest_Cf{
					Cf: &CloudfoundryRequest{},
				},
			},
			expectedResult: false,
		},
	}

	boshResolver, err := NewResolverWithMockBoshAPI(nil) // NewBoshResolver(bosh.Environment{}, 8083)
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

// TODO: Test for getInstances? (is included in resolve)

func TestValidateBoshEndpointRequest(t *testing.T) {
	tests := []struct {
		name        string
		req         *BoshRequest
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
			req:         &BoshRequest{},
			wantErr:     true,
			expectedErr: errEmptyField,
		},

		{
			name:        "Bosh metadata Token is not present",
			req:         &BoshRequest{Deployment: "cf", Groups: []string{"router"}},
			wantErr:     true,
			expectedErr: errEmptyField,
		},
		{
			name:        "Bosh metadata Deployment field is not present",
			req:         &BoshRequest{Token: "123d24", Groups: []string{"router"}},
			wantErr:     true,
			expectedErr: errEmptyField,
		},
		{
			name:        "Bosh metadata Groups field is not present",
			req:         &BoshRequest{Token: "123d24", Deployment: "cf", Environment: "bosh"},
			wantErr:     true,
			expectedErr: errEmptyField,
		},
		{
			name:        "Bosh metadata Environment field is not present",
			req:         &BoshRequest{Token: "123d24", Deployment: "cf", Groups: []string{"router"}},
			wantErr:     true,
			expectedErr: errEmptyField,
		},
		{
			name: "Valid request",
			req: &BoshRequest{
				Token: "123d24", Deployment: "cf", Groups: []string{"router"}, Environment: "bosh",
			},
			wantErr:     false,
			expectedErr: nil,
		},
	}

	boshResolver, err := NewResolverWithMockBoshAPI(nil) // NewBoshResolver(bosh.Environment{}, 8083)
	if err != nil {
		t.Error(err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testEndpointRequest := &EndpointRequest{Request: &EndpointRequest_Bosh{tt.req}}

			err = boshResolver.validate(testEndpointRequest)
			if (err != nil) != tt.wantErr {
				t.Errorf("wantErr = %v, error = %v", tt.wantErr, err)
			}
			if tt.expectedErr != nil && !errors.Is(err, tt.expectedErr) {
				t.Errorf("expectedErr = %v, error = %v", tt.expectedErr, err)
			}
		})
	}
}
