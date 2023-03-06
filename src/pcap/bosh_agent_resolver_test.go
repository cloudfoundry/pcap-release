package pcap

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cloudfoundry/pcap-release/src/pcap/bosh"
	"github.com/cloudfoundry/pcap-release/src/pcap/test"
	"go.uber.org/zap"
	"reflect"
	"strings"
	"testing"
	"time"
)

func NewAgentResolverWithMockBoshAPI(responses map[string]string) (*BoshAgentResolver, error) {
	jwtapi, _ := test.MockjwtAPI()
	boshAPI := test.MockBoshDirectorAPI(responses, jwtapi.URL)
	environment := bosh.Environment{
		Alias: "bosh",
		Url:   boshAPI.URL,
	}
	boshAgentResolver, err := NewBoshAgentResolver(environment, 8083)
	if err != nil {
		return nil, err
	}
	boshAgentResolver.uaaURLs = []string{jwtapi.URL}
	return boshAgentResolver, nil
}

func TestNewBoshAgentResolver(t *testing.T) {
	jwtapi, _ := test.MockjwtAPI()
	boshAPI := test.MockBoshDirectorAPI(nil, jwtapi.URL)

	tests := []struct {
		name        string
		environment bosh.Environment
		wantErr     bool
		expectedErr error
		agentPort   int //TODO: will this be a parameter?
	}{
		{
			name: "validEnvironment",
			environment: bosh.Environment{
				Alias: "validEnvironment",
				Url:   boshAPI.URL,
			},
			wantErr:   false,
			agentPort: 8083,
		},
		{
			name:        "empty environment",
			environment: bosh.Environment{},
			wantErr:     true,
			expectedErr: nil,
			agentPort:   0,
		},
		//TODO: test for CaCert, unavailable Director API, unparseable Director API
	}

	for _, test := range tests {
		boshAgentResolver, err := NewBoshAgentResolver(test.environment, test.agentPort)
		if err != nil {
			if (err != nil) != test.wantErr {
				t.Errorf("wantErr = %v, error = %v", test.wantErr, err)
			}
			if test.expectedErr != nil && !errors.Is(err, test.expectedErr) {
				t.Errorf("expectedErr = %v,\n\t\t\t\t\t\t\t   actualErr = %v", test.expectedErr, err)
			}
			if boshAgentResolver == nil {
				t.Error("boshAgentResolver is nil")
			}
		}

	}

}

func TestAuthenticate(t *testing.T) {
	bar, err := NewAgentResolverWithMockBoshAPI(nil)
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
			expectedErr: nil, //TODO: custom error comparison currently not implemented, see wrap.go:53
			//expectedErr: fmt.Errorf("could not verify token eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vMTAuMC4zLjExOjg0NDMvdG9rZW5fa2V5cyIsImtpZCI6InVhYS1qd3Qta2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiIwZWNmODIxYjVmYzI0YTBmODczOWM5MmJkOGY2YzYyMi1yIiwic3ViIjoiMDY4ZmEwODItMDdkNy00NjRjLWE1MWEtZmFkMzdiNGQ2MDViIiwiaWF0IjoxNjc3NTM0Mjg3LCJleHAiOjE2Nzc2MjA2ODcsImNpZCI6ImJvc2hfY2xpIiwiY2xpZW50X2lkIjoiYm9zaF9jbGkiLCJpc3MiOiJodHRwczovLzEwLjAuMy4xMTo4NDQzL29hdXRoL3Rva2VuIiwiemlkIjoidWFhIiwiYXVkIjpbIm9wZW5pZCIsImJvc2hfY2xpIiwiYm9zaCJdLCJncmFudGVkX3Njb3BlcyI6WyJvcGVuaWQiLCJib3NoLmFkbWluIl0sImFtciI6WyJwd2QiXSwiYXV0aF90aW1lIjoxNjc3NTM0Mjg3LCJncmFudF90eXBlIjoicGFzc3dvcmQiLCJ1c2VyX25hbWUiOiJoLmk1NTQwNzYuOTFiNjc1Iiwib3JpZ2luIjoidWFhIiwidXNlcl9pZCI6IjA2OGZhMDgyLTA3ZDctNDY0Yy1hNTFhLWZhZDM3YjRkNjA1YiIsInJldl9zaWciOiJjMGRkMTY0MSJ9.o7t1HSihRZNrHKeCynj5K8xM5EixOMr33F37N7i2Zy-I2d8T9LLXCbY9nczQboSG2UtDFu-ztr7xMFwpsCYzVgGItWPBMY62tk4GVir1zFYEDChFXF6vaL3Lv9Y1L9AOwtT6Nr47jYY5XxkLmVgjfXb2wDx7lL8OG0BvVmKrQDtZuUlYhyXQNDkhBHQlXh5TqK07LgPzOoWgoVcNGNlpjj3hOnHNAq-gexNqJHtIBJ-0AdcadyE3wrKWCxeuQGkEnnMG3M2ByVoFd6_V2UnizxCnIpaoVOLJqywUyxOecmALLg4c9M6Bymkv5oR_CgbMGcVTxocwGgDYXVZ20TpbOg (header 'jku' https://10.0.3.11:8443/token_keys did not match any UAA base URLs reported by the BOSH Director: [%v])", bar.uaaURLs[0]),
		},
		{
			name:        "invalid token - not a token",
			token:       "notatoken",
			wantErr:     true,
			expectedErr: nil, //TODO: custom error comparison currently not implemented, see wrap.go:53
			//expectedErr: fmt.Errorf("could not verify token notatoken (token contains an invalid number of segments)"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err = bar.authenticate(test.token)
			if (err != nil) != test.wantErr {
				t.Errorf("wantErr = %v, error = %v", test.wantErr, err)
			}
			if test.expectedErr != nil && !errors.Is(err, test.expectedErr) {
				t.Errorf("expectedErr = %v,\n\t\t\t\t\t\t\t   actualErr = %v", test.expectedErr, err)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	log := zap.L() //TODO: Proper log handling?
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

	var haproxyInstances []bosh.Instance

	timeString := "2022-09-26T21:28:39Z"
	timestamp, err := time.Parse(time.RFC3339, timeString)
	for _, endpoint := range expectedAgentEndpoints {

		parts := strings.Split(endpoint.Identifier, "/")
		job, id := parts[0], parts[1]

		instance := bosh.Instance{
			AgentId:     endpoint.Identifier,
			Cid:         "agent_id:a9c3cda6-9cd9-457f-aad4-143405bf69db;resource_group_name:rg-azure-cfn01",
			Job:         job,
			Index:       0,
			Id:          id,
			Az:          "z1",
			Ips:         []string{endpoint.IP},
			VmCreatedAt: timestamp,
			ExpectsVm:   true,
		}
		haproxyInstances = append(haproxyInstances, instance)
	}

	instances, err := json.Marshal(haproxyInstances)

	responses := map[string]string{
		fmt.Sprintf("/deployments/%v/instances", deploymentName): string(instances),
	}

	boshAgentResolver, err := NewAgentResolverWithMockBoshAPI(responses)
	if err != nil {
		t.Errorf("received unexpected error = %v", err)
	}

	validToken, err := test.GetValidToken(boshAgentResolver.uaaURLs[0])
	if err != nil {
		t.Error(err)
	}

	request := &EndpointRequest{
		Request: &EndpointRequest_Bosh{Bosh: &BoshRequest{
			Token:      validToken,
			Deployment: deploymentName,
			Groups:     []string{"test-instance-group"},
			Instances:  nil,
		}},
	}

	agentEndpoints, err := boshAgentResolver.resolve(request, log)
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
					Bosh: &BoshRequest{},
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

	boshAgentResolver, err := NewAgentResolverWithMockBoshAPI(nil) // NewBoshAgentResolver(bosh.Environment{}, 8083)
	if err != nil {
		t.Error(err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := boshAgentResolver.canResolve(test.req)
			if test.expectedResult != result {
				t.Errorf("expectedResult = %v, result = %v", test.expectedResult, result)
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
			req:         &BoshRequest{Token: "123d24", Deployment: "cf"},
			wantErr:     true,
			expectedErr: errEmptyField,
		},
		{
			name:        "Valid request",
			req:         &BoshRequest{Token: "123d24", Deployment: "cf", Groups: []string{"router"}},
			wantErr:     false,
			expectedErr: nil,
		},
	}

	boshAgentResolver, err := NewAgentResolverWithMockBoshAPI(nil) // NewBoshAgentResolver(bosh.Environment{}, 8083)
	if err != nil {
		t.Error(err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testEndpointRequest := &EndpointRequest{Request: &EndpointRequest_Bosh{test.req}}

			err := boshAgentResolver.validate(testEndpointRequest)
			if (err != nil) != test.wantErr {
				t.Errorf("wantErr = %v, error = %v", test.wantErr, err)
			}
			if test.expectedErr != nil && !errors.Is(err, test.expectedErr) {
				t.Errorf("expectedErr = %v, error = %v", test.expectedErr, err)
			}
		})
	}
}
