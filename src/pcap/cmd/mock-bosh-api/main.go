package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cloudfoundry/pcap-release/src/pcap/bosh"
	"github.com/cloudfoundry/pcap-release/src/pcap/test"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"time"
)

func main() {
	jwtapi, _ := test.MockjwtAPI()
	responses := prepareMockBoshDirectorResponse()
	boshAPI := test.MockBoshDirectorAPI(responses, jwtapi.URL)
	defer boshAPI.Close()

	fmt.Printf("jwtapi listening on %v\n", jwtapi.URL)
	fmt.Printf("boshapi listening on %v\n", boshAPI.URL)

	for {
		updateAPIConfig("/Users/I554076/repos/pcap-release/src/pcap/test/api-test-config.yml", boshAPI.URL)
		updateBoshCLIConfig("/Users/I554076/repos/pcap-release/src/pcap/test/bosh_config_temp", boshAPI.URL, jwtapi.URL)
		time.Sleep(1 * time.Minute)
	}
}

func prepareMockBoshDirectorResponse() map[string]string {
	timeString := "2022-09-26T21:28:39Z"
	timestamp, _ := time.Parse(time.RFC3339, timeString)

	haproxyInstances := []bosh.Instance{
		{
			AgentId:     "idk",
			Cid:         "agent_id:a9c3cda6-9cd9-457f-aad4-143405bf69db;resource_group_name:rg-azure-cfn01",
			Job:         "ha_proxy_z1",
			Index:       0,
			Id:          "1234",
			Az:          "z1",
			Ips:         []string{"127.0.0.1"},
			VmCreatedAt: timestamp,
			ExpectsVm:   true,
		},
	}

	instances, _ := json.Marshal(haproxyInstances)

	responses := map[string]string{
		"/deployments/haproxy/instances": string(instances),
	}
	return responses
}

func updateAPIConfig(file string, boshURL string) {
	config := fmt.Sprintf(`log_level: debug
buffer:
  size: 100
  upperLimit: 95
  lowerLimit: 90
common_config:
  id: "testapi"
  listen:
    port: 8080
agents:
  port: 8083
bosh_environments:
  - alias: "bosh"
    url: "%v"
drain_timeout: 10s
concurrent_captures: 5
`, boshURL)

	err := os.WriteFile(file, []byte(config), fs.ModePerm)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Wrote api config to %v\n", file)
}
func updateBoshCLIConfig(file string, boshURL string, jwtAPIurl string) {
	token, err := GetValidToken(jwtAPIurl)
	if err != nil {
		fmt.Errorf("could not generate valid token %v", err.Error())
	}

	config := fmt.Sprintf(`environments:
    - access_token: %v
      access_token_type: bearer
      alias: bosh
      ca_cert: |-
        -----BEGIN CERTIFICATE-----
        MIIC+zCCAeOgAwIBAgIUfW2l1prr7oFdFkaTju/vKq1Ne0cwDQYJKoZIhvcNAQEL
        BQAwDTELMAkGA1UEAxMCY2EwHhcNMjMwMjA5MTUyNTIzWhcNMjQwMjA5MTUyNTIz
        WjANMQswCQYDVQQDEwJjYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
        AJRgyZM2OBW4OrwVCZwuP+PBCTbm9v5o8VYOPzQTDDr2KPh8VlKVB78afL5YfoGP
        30t85FySV6O0NI9agl/5ZL2M4b3XavbNzPaB7Mr6fYMfURKIBAEg4VSQsz+9Wi7Y
        dSJIiF1Rons0OWm2040DNq4pGgou+3BLmvY408h0Eevr9l+bDhiRzJifX4eEybcU
        pMtMDf7Nq5tBKj5XLTDlGoLNd5l8ffXJu8eexN/IclBlQmpVtkhNpox9JxvEXIOb
        AGsCMlwESd1yxQM7Nn8Efxq54sa+gsDa2YrQpsPewIB1TeW8ClRHcS7AvV6Y4+lG
        N0aecEFn+bQCNNzpRzxK8lsCAwEAAaNTMFEwHQYDVR0OBBYEFMa+qoGtsZyLOVa+
        Uw7Z4Op6kL5QMB8GA1UdIwQYMBaAFMa+qoGtsZyLOVa+Uw7Z4Op6kL5QMA8GA1Ud
        EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGe50cqiHO+TeBbQ7L11Pudx
        0ycW7Pmi2NBp9ipIOMNgvY4mmyIeD3XgzBnfvNfQg5Wwpr68W1QgDjIRbYr63Ob0
        HTYHpdT9fWRieg7SnJVd/mdaHPxhSve6mqXoR3u7lvEOSXDWTwSpAOVPkTigWZET
        CmfCX/gWbpQFgf8f+5RTomdB+V1euPUqi8AmpMjTE6BsZCV52UJcibxMqqxvqqqg
        OlIRhLczx0hdiDxa4qvQyLYLKSa1y+47WQJj1b7h6lbN1Awx6OQtwAK7/vyBLRqK
        s3Zphxo1fv8iME3Zn8hd+ZezmHdaQce4IhlPlM1/YJi3TxiI84rOU0aac1bFFMk=
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        MIIC+zCCAeOgAwIBAgIUCmTXEemsNV3F0vP3q9A04TzzkmQwDQYJKoZIhvcNAQEL
        BQAwDTELMAkGA1UEAxMCY2EwHhcNMjMwMjEwMTk1NjI5WhcNMjQwMjEwMTk1NjI5
        WjANMQswCQYDVQQDEwJjYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
        AKpBuhRFjjSBIyehU2Ocl6L9I3csNbMyiNh7XOSLkOHLK4pgcGqIvMnxfbyoriwu
        OuGPJ7+XWhVpf+AIQpCZylBKPTKDDqV27z+BIAwMx40LdZvqfPvaZdI84i8l6SlF
        QcAEyQSN5Q40rLY6Gj22swva7ocZiqTOd9udGGbekYWbyR6UBDaNEevLHhvm5lWE
        NCHESTbMGemb+AC5gPVaEkXEcygVXyNHSulB7fANmEjCUlje0N6Av+zaebwZYGsI
        p2pcI/sSJm4gJItRUWsyl4vNma2Slsqfy+epZQOxwf2DxwmlJaVcto0qtOAwuxhp
        Vbh7BgL4/uyrq9BA2H8z950CAwEAAaNTMFEwHQYDVR0OBBYEFEUEGrd5u2UV6vz2
        Ty44rfKnx1p2MB8GA1UdIwQYMBaAFEUEGrd5u2UV6vz2Ty44rfKnx1p2MA8GA1Ud
        EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABJZ5c9g051c4KuT2LCNX5pl
        zYXICM231S4+3AqufmcOndahxDcnazS8njKP0EghRdnE+yROtLLVKdOSIUJrrvVO
        VuIrJ+eQ4tprDoIxV5jjpnjUiFgNdL3nPL3JpJzW5XousEWSfYfCZQ9wNpslDB/W
        9SMSAbjLsQTHT4CW4+5n8nBpHhV2JEbAu6NlTZFIn5zcaxB+ZAijVh2l237d87p9
        irwrngNARqkOSiPSrPSp4dpUn6Vj4nZxk3T2FgA4Gpp5+R2lps2zOuRimYnXGQnz
        35tMBsDP/HYSv6cLBCcgCm/g4p5Rm9v+1pgTx52Yl1zZvTJ/oIMOkZKbW/DKzwQ=
        -----END CERTIFICATE-----
      refresh_token: %v
      url: %v
`, token, token, boshURL)

	err = os.WriteFile(file, []byte(config), fs.ModePerm)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Wrote bosh CLI config to %v\n", file)
	fmt.Printf("Generated Token %v\n", token)
}

func GetValidToken(uaaURL string) (string, error) {
	fullURL, err := url.Parse(fmt.Sprintf("%v/oauth/token", uaaURL))
	if err != nil {
		return "", err
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
		return "", err
	}

	var newTokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	err = json.NewDecoder(res.Body).Decode(&newTokens)
	if err != nil {
		return "", err
	}
	return newTokens.AccessToken, nil
}
