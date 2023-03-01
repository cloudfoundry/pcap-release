package pcap

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cloudfoundry/pcap-release/src/pcap/bosh"
	"github.com/cloudfoundry/pcap-release/src/pcap/test"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func NewAgentResolverWithMockBoshAPI(responses map[string]string) *BoshAgentResolver {
	jwtapi, _ := test.MockjwtAPI()
	boshAPI := test.MockBoshDirectorAPI(responses, jwtapi.URL)
	return &BoshAgentResolver{
		environment: bosh.Environment{
			Alias: "bosh",
			Url:   boshAPI.URL,
		},
		uaaURLS: []string{jwtapi.URL},
	}
}

func GetValidToken(uaaURL string) string {
	fullURL, err := url.Parse(fmt.Sprintf("%v/oauth/token", uaaURL))
	if err != nil {
		panic(err)
	}
	req := http.Request{
		Method: http.MethodPost,
		URL:    fullURL,
		Header: http.Header{
			"Accept":        {"application/json"},
			"Content-Type":  {"application/x-www-form-urlencoded"},
			"Authorization": {fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte("bosh_cli:")))}, // TODO: the client name is also written in the token
		},
		Body: io.NopCloser(bytes.NewReader([]byte(url.Values{
			"grant_type": {"refresh_token"},
		}.Encode()))),
	}
	res, err := http.DefaultClient.Do(&req)
	if err != nil {
		panic(err)
	}

	var newTokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	err = json.NewDecoder(res.Body).Decode(&newTokens)
	if err != nil {
		panic(err)
	}
	return newTokens.AccessToken
}
func TestAuthenticate(t *testing.T) {
	bar := NewAgentResolverWithMockBoshAPI(nil)

	tests := []struct {
		name        string
		token       string
		wantErr     bool
		expectedErr error
	}{
		{
			name:        "valid token",
			token:       GetValidToken(bar.uaaURLS[0]),
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name:        "invalid token - mismatching jku",
			token:       "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vMTAuMC4zLjExOjg0NDMvdG9rZW5fa2V5cyIsImtpZCI6InVhYS1qd3Qta2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiIwZWNmODIxYjVmYzI0YTBmODczOWM5MmJkOGY2YzYyMi1yIiwic3ViIjoiMDY4ZmEwODItMDdkNy00NjRjLWE1MWEtZmFkMzdiNGQ2MDViIiwiaWF0IjoxNjc3NTM0Mjg3LCJleHAiOjE2Nzc2MjA2ODcsImNpZCI6ImJvc2hfY2xpIiwiY2xpZW50X2lkIjoiYm9zaF9jbGkiLCJpc3MiOiJodHRwczovLzEwLjAuMy4xMTo4NDQzL29hdXRoL3Rva2VuIiwiemlkIjoidWFhIiwiYXVkIjpbIm9wZW5pZCIsImJvc2hfY2xpIiwiYm9zaCJdLCJncmFudGVkX3Njb3BlcyI6WyJvcGVuaWQiLCJib3NoLmFkbWluIl0sImFtciI6WyJwd2QiXSwiYXV0aF90aW1lIjoxNjc3NTM0Mjg3LCJncmFudF90eXBlIjoicGFzc3dvcmQiLCJ1c2VyX25hbWUiOiJoLmk1NTQwNzYuOTFiNjc1Iiwib3JpZ2luIjoidWFhIiwidXNlcl9pZCI6IjA2OGZhMDgyLTA3ZDctNDY0Yy1hNTFhLWZhZDM3YjRkNjA1YiIsInJldl9zaWciOiJjMGRkMTY0MSJ9.o7t1HSihRZNrHKeCynj5K8xM5EixOMr33F37N7i2Zy-I2d8T9LLXCbY9nczQboSG2UtDFu-ztr7xMFwpsCYzVgGItWPBMY62tk4GVir1zFYEDChFXF6vaL3Lv9Y1L9AOwtT6Nr47jYY5XxkLmVgjfXb2wDx7lL8OG0BvVmKrQDtZuUlYhyXQNDkhBHQlXh5TqK07LgPzOoWgoVcNGNlpjj3hOnHNAq-gexNqJHtIBJ-0AdcadyE3wrKWCxeuQGkEnnMG3M2ByVoFd6_V2UnizxCnIpaoVOLJqywUyxOecmALLg4c9M6Bymkv5oR_CgbMGcVTxocwGgDYXVZ20TpbOg",
			wantErr:     true,
			expectedErr: nil, //TODO: custom error comparison currently not implemented, see wrap.go:53
			//expectedErr: fmt.Errorf("could not verify token eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vMTAuMC4zLjExOjg0NDMvdG9rZW5fa2V5cyIsImtpZCI6InVhYS1qd3Qta2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiIwZWNmODIxYjVmYzI0YTBmODczOWM5MmJkOGY2YzYyMi1yIiwic3ViIjoiMDY4ZmEwODItMDdkNy00NjRjLWE1MWEtZmFkMzdiNGQ2MDViIiwiaWF0IjoxNjc3NTM0Mjg3LCJleHAiOjE2Nzc2MjA2ODcsImNpZCI6ImJvc2hfY2xpIiwiY2xpZW50X2lkIjoiYm9zaF9jbGkiLCJpc3MiOiJodHRwczovLzEwLjAuMy4xMTo4NDQzL29hdXRoL3Rva2VuIiwiemlkIjoidWFhIiwiYXVkIjpbIm9wZW5pZCIsImJvc2hfY2xpIiwiYm9zaCJdLCJncmFudGVkX3Njb3BlcyI6WyJvcGVuaWQiLCJib3NoLmFkbWluIl0sImFtciI6WyJwd2QiXSwiYXV0aF90aW1lIjoxNjc3NTM0Mjg3LCJncmFudF90eXBlIjoicGFzc3dvcmQiLCJ1c2VyX25hbWUiOiJoLmk1NTQwNzYuOTFiNjc1Iiwib3JpZ2luIjoidWFhIiwidXNlcl9pZCI6IjA2OGZhMDgyLTA3ZDctNDY0Yy1hNTFhLWZhZDM3YjRkNjA1YiIsInJldl9zaWciOiJjMGRkMTY0MSJ9.o7t1HSihRZNrHKeCynj5K8xM5EixOMr33F37N7i2Zy-I2d8T9LLXCbY9nczQboSG2UtDFu-ztr7xMFwpsCYzVgGItWPBMY62tk4GVir1zFYEDChFXF6vaL3Lv9Y1L9AOwtT6Nr47jYY5XxkLmVgjfXb2wDx7lL8OG0BvVmKrQDtZuUlYhyXQNDkhBHQlXh5TqK07LgPzOoWgoVcNGNlpjj3hOnHNAq-gexNqJHtIBJ-0AdcadyE3wrKWCxeuQGkEnnMG3M2ByVoFd6_V2UnizxCnIpaoVOLJqywUyxOecmALLg4c9M6Bymkv5oR_CgbMGcVTxocwGgDYXVZ20TpbOg (header 'jku' https://10.0.3.11:8443/token_keys did not match any UAA base URLs reported by the BOSH Director: [%v])", bar.uaaURLS[0]),
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
			err := bar.authenticate(test.token)
			if (err != nil) != test.wantErr {
				t.Errorf("wantErr = %v, error = %v", test.wantErr, err)
			}
			if test.expectedErr != nil && !errors.Is(err, test.expectedErr) {
				t.Errorf("expectedErr = %v,\n\t\t\t\t\t\t\t   actualErr = %v", test.expectedErr, err)
			}
		})
	}
}
func TestAuthenticate_Success(t *testing.T) {
	bar := NewAgentResolverWithMockBoshAPI(nil)

	//bar.Setup()
	//token := "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vMTAuMC4zLjExOjg0NDMvdG9rZW5fa2V5cyIsImtpZCI6InVhYS1qd3Qta2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiI4MWNjYWU0MmFjMjA0MWUxOTJiOGVmMWYwOWFmZGEyOSIsInN1YiI6IjA2OGZhMDgyLTA3ZDctNDY0Yy1hNTFhLWZhZDM3YjRkNjA1YiIsInNjb3BlIjpbIm9wZW5pZCIsImJvc2guYWRtaW4iXSwiY2xpZW50X2lkIjoiYm9zaF9jbGkiLCJjaWQiOiJib3NoX2NsaSIsImF6cCI6ImJvc2hfY2xpIiwiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIiwidXNlcl9pZCI6IjA2OGZhMDgyLTA3ZDctNDY0Yy1hNTFhLWZhZDM3YjRkNjA1YiIsIm9yaWdpbiI6InVhYSIsInVzZXJfbmFtZSI6ImguaTU1NDA3Ni45MWI2NzUiLCJlbWFpbCI6ImguaTU1NDA3Ni45MWI2NzVAMTAuMC4zLjExOjg0NDMiLCJhdXRoX3RpbWUiOjE2Nzc1MzQyODcsInJldl9zaWciOiJjMGRkMTY0MSIsImlhdCI6MTY3NzU3ODg2NCwiZXhwIjoxNjc3NTc4OTg0LCJpc3MiOiJodHRwczovLzEwLjAuMy4xMTo4NDQzL29hdXRoL3Rva2VuIiwiemlkIjoidWFhIiwiYXVkIjpbImJvc2hfY2xpIiwiYm9zaCIsIm9wZW5pZCJdfQ.dyJs_gutnORg2UGSf191NBDQu5tHN8AwoldZwZtAN7FkiHK8XXr_uzs-EYzhJ0f0TsngrjSPUypdJAKsWToAY3q2KXFhTi5s5nN6_s7jkKbNrezhddEnrzYqFZiyGGNY0N01marAgY2DefdMrLdSekVCHP-0DntS8yL7XpyildqXvlvMcTZRvO5PL81xr_QuXOimgO7C0yQtc04YvmzD1N5CE06hjAcC3O9hyduDIysEKINiSyxcJJeVDfaQpm5vxlOXf-Q-yKiN9nPBSctgukiT4Fozm8jpCa2yidcZwkzLTbYaXAMgjgv__-jID664aRwXrgSpc8300YZa6fLefQ"
	token := GetValidToken(bar.uaaURLS[0])
	err := bar.authenticate(token)
	if err != nil {
		t.Errorf("received unexpected error = %v", err)
	}
}

func TestAuthenticate_InvalidToken(t *testing.T) {
	boshAgentResolver := NewAgentResolverWithMockBoshAPI(nil)
	// TODO: token with invalid jku
	invalidToken := "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vMTAuMC4zLjExOjg0NDMvdG9rZW5fa2V5cyIsImtpZCI6InVhYS1qd3Qta2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiIwZWNmODIxYjVmYzI0YTBmODczOWM5MmJkOGY2YzYyMi1yIiwic3ViIjoiMDY4ZmEwODItMDdkNy00NjRjLWE1MWEtZmFkMzdiNGQ2MDViIiwiaWF0IjoxNjc3NTM0Mjg3LCJleHAiOjE2Nzc2MjA2ODcsImNpZCI6ImJvc2hfY2xpIiwiY2xpZW50X2lkIjoiYm9zaF9jbGkiLCJpc3MiOiJodHRwczovLzEwLjAuMy4xMTo4NDQzL29hdXRoL3Rva2VuIiwiemlkIjoidWFhIiwiYXVkIjpbIm9wZW5pZCIsImJvc2hfY2xpIiwiYm9zaCJdLCJncmFudGVkX3Njb3BlcyI6WyJvcGVuaWQiLCJib3NoLmFkbWluIl0sImFtciI6WyJwd2QiXSwiYXV0aF90aW1lIjoxNjc3NTM0Mjg3LCJncmFudF90eXBlIjoicGFzc3dvcmQiLCJ1c2VyX25hbWUiOiJoLmk1NTQwNzYuOTFiNjc1Iiwib3JpZ2luIjoidWFhIiwidXNlcl9pZCI6IjA2OGZhMDgyLTA3ZDctNDY0Yy1hNTFhLWZhZDM3YjRkNjA1YiIsInJldl9zaWciOiJjMGRkMTY0MSJ9.o7t1HSihRZNrHKeCynj5K8xM5EixOMr33F37N7i2Zy-I2d8T9LLXCbY9nczQboSG2UtDFu-ztr7xMFwpsCYzVgGItWPBMY62tk4GVir1zFYEDChFXF6vaL3Lv9Y1L9AOwtT6Nr47jYY5XxkLmVgjfXb2wDx7lL8OG0BvVmKrQDtZuUlYhyXQNDkhBHQlXh5TqK07LgPzOoWgoVcNGNlpjj3hOnHNAq-gexNqJHtIBJ-0AdcadyE3wrKWCxeuQGkEnnMG3M2ByVoFd6_V2UnizxCnIpaoVOLJqywUyxOecmALLg4c9M6Bymkv5oR_CgbMGcVTxocwGgDYXVZ20TpbOg"
	err := boshAgentResolver.authenticate(invalidToken)
	if err == nil {
		t.Error("expected token verification error")
	}
}

func TestBoshAgentResolver_Setup(t *testing.T) {
	//allvalid
	//certinvalid
	boshAgentResolver := NewAgentResolverWithMockBoshAPI(nil)
	err := boshAgentResolver.Setup()
	if err != nil {
		t.Errorf("received unexpected error = %v", err)
	}
}

func TestResolve(t *testing.T) {
	log := zap.L() //TODO: Proper log handling?
	deploymentName := "test-deployment"

	expectedAgentEndpoints := []AgentEndpoint{
		{
			IP:         "192.168.0.1",
			Port:       8080, // from AgentMTLS{DefaultPort: 8080}
			Identifier: "ha_proxy_z1/Testagent1",
		},
		{
			IP:         "192.168.0.2",
			Port:       8080,
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

	boshAgentResolver := NewAgentResolverWithMockBoshAPI(responses)
	err = boshAgentResolver.Setup()
	if err != nil {
		t.Errorf("received unexpected error = %v", err)
	}

	request := &EndpointRequest{
		Capture: &Capture_Bosh{Bosh: &BoshQuery{
			Token:      GetValidToken(boshAgentResolver.uaaURLS[0]),
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
				Capture: &Capture_Bosh{
					Bosh: &BoshQuery{},
				},
			},
			expectedResult: true,
		},
		{
			name: "CFRequest",
			req: &EndpointRequest{
				Capture: &Capture_Cf{
					Cf: &CloudfoundryQuery{},
				},
			},
			expectedResult: false,
		},
	}

	boshAgentResolver := NewBoshAgentResolver(bosh.Environment{}, AgentMTLS{DefaultPort: 8080})

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

	boshAgentResolver := NewBoshAgentResolver(bosh.Environment{}, AgentMTLS{DefaultPort: 8080})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testEndpointRequest := &EndpointRequest{Capture: &Capture_Bosh{test.req}}

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
