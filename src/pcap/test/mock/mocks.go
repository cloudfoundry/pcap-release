//nolint:mnd // These tests include a lot of magic numbers that are part of the test scenarios.
package mock

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/cloudfoundry/pcap-release/src/pcap"

	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
)

func MustParseURL(rawURL string) *url.URL {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return parsedURL
}

func NewMockJWTAPI() (*httptest.Server, string) {
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	jku := ts.URL + "/token_keys"

	publicPemKey, token := verifyJWTTokenMock(jku)

	// the response body must not contain any linebreaks or json parsing will fail
	re := regexp.MustCompile(`\r?\n`)
	publicPemKeyNoLineBreak := re.ReplaceAllString(publicPemKey, "\\n")

	jsonString := fmt.Sprintf(`{"keys":[{"kty": "RSA","e": "AQAB","use": "sig","kid": "uaa-jwt-key-1","alg": "RS256","value": "%v","n": ""}]}`, publicPemKeyNoLineBreak)

	mux.HandleFunc("/token_keys", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")

		_, err := writer.Write([]byte(jsonString))
		if err != nil {
			zap.L().Warn("failed to write token_keys response", zap.Error(err))
		}
	})

	mux.HandleFunc("/oauth/token", func(writer http.ResponseWriter, _ *http.Request) {
		response := fmt.Sprintf(`{"access_token": "%v","refresh_token": "%v","token_type": "bearer"}`, token, token)
		_, err := writer.Write([]byte(response))
		if err != nil {
			zap.L().Warn("failed to write /oauth/token response", zap.Error(err))
		}
	})

	return ts, token
}

func NewResolverWithMockBoshAPI(responses map[string]string) (*pcap.BoshResolver, *httptest.Server, *httptest.Server, error) {
	config := pcap.BoshResolverConfig{
		AgentPort:  8083,
		TokenScope: "bosh.admin",
	}
	return NewResolverWithMockBoshAPIWithConfig(responses, config)
}

func NewResolverWithMockBoshAPIWithConfig(responses map[string]string, config pcap.BoshResolverConfig) (*pcap.BoshResolver, *httptest.Server, *httptest.Server, error) {
	jwtapi, _ := NewMockJWTAPI()
	boshAPI := NewMockBoshDirectorAPI(responses, jwtapi.URL)

	config.RawDirectorURL = boshAPI.URL

	boshResolver, err := pcap.NewBoshResolver(config)
	if err != nil {
		return nil, nil, nil, err
	}
	boshResolver.UaaURLs = []string{jwtapi.URL}
	return boshResolver, boshAPI, jwtapi, nil
}

func NewDefaultResolverWithMockBoshAPIWithEndpoints(endpoints []pcap.AgentEndpoint, deploymentName string) (*pcap.BoshResolver, *httptest.Server, *httptest.Server, error) {
	config := pcap.BoshResolverConfig{
		AgentPort:  8083,
		TokenScope: "bosh.admin",
	}
	return NewResolverWithMockBoshAPIWithEndpoints(endpoints, config, deploymentName)
}

func NewResolverWithMockBoshAPIWithEndpoints(endpoints []pcap.AgentEndpoint, config pcap.BoshResolverConfig, deploymentName string) (*pcap.BoshResolver, *httptest.Server, *httptest.Server, error) {
	var deploymentInstances []pcap.BoshInstance

	timeString := "2022-09-26T21:28:39Z"
	timestamp, _ := time.Parse(time.RFC3339, timeString)
	for _, endpoint := range endpoints {
		parts := strings.Split(endpoint.Identifier, "/")
		job, id := parts[0], parts[1]

		instance := pcap.BoshInstance{
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
		deploymentInstances = append(deploymentInstances, instance)
	}

	instances, err := json.Marshal(deploymentInstances)
	if err != nil {
		panic(err)
	}

	responses := map[string]string{
		fmt.Sprintf("/deployments/%v/instances", deploymentName): string(instances),
	}

	return NewResolverWithMockBoshAPIWithConfig(responses, config)
}

func NewMockBoshDirectorAPI(responses map[string]string, url string) *httptest.Server {
	jsonTemplate := `{
		"name": "bosh-azure-cfn01",
		"uuid": "f0ceb485-e188-4b9f-b3d5-fb2067aad3c2",
		"version": "273.1.0 (00000000)",
		"user": null,
		"cpi": "azure_cpi",
		"stemcell_os": "-",
		"stemcell_version": "1.8",
		"user_authentication": {
		  "type": "uaa",
		  "options": {
			"url": "{{.UaaURL}}",
			"urls": [
			  "{{.UaaURL}}"
			]
		  }
		}
	}`

	type BoshAPIMock struct {
		UaaURL string
	}
	var boshapi BoshAPIMock

	responseTemplate := template.Must(template.New("boshapi").Parse(jsonTemplate))

	mux := http.NewServeMux()
	mux.HandleFunc("/info", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		err := responseTemplate.Execute(writer, boshapi)
		if err != nil {
			zap.L().Panic("failed to write bosh /info response", zap.Error(err))
		}
	})

	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")

		response, ok := responses[request.URL.Path]
		if !ok {
			writer.WriteHeader(http.StatusNotFound)
			return
		}

		_, err := writer.Write([]byte(response))
		if err != nil {
			zap.L().Panic("failed to write bosh / response", zap.Error(err))
		}
	})

	ts := httptest.NewServer(mux)
	boshapi.UaaURL = url

	return ts
}

func verifyJWTTokenMock(jku string) (string, string) {
	type payload struct {
		Scope     []string  `json:"scope"`
		ClientID  string    `json:"client_id"`
		Cid       string    `json:"cid"`
		Azp       string    `json:"azp"`
		GrantType string    `json:"grant_type"`
		UserID    string    `json:"user_id"`
		Origin    string    `json:"origin"`
		User      string    `json:"user_name"`
		Email     string    `json:"email"`
		AuthTime  time.Time `json:"auth_time"`
		RevSig    string    `json:"rev_sig"`
		Zid       string    `json:"zid"`
		jwt.RegisteredClaims
	}

	// Create the claims
	claims := payload{

		Scope: []string{
			"openid",
			"bosh.admin",
		},
		ClientID:  "bosh_cli",
		Cid:       "bosh_cli",
		Azp:       "bosh_cli",
		GrantType: "password",
		UserID:    "f62c94ae-2552-411b-9f8e-9ad181c50b40",
		Origin:    "uaa",
		User:      "h.example",
		Email:     "h.example@192.168.1.11:8443",
		AuthTime:  time.Now(),
		RevSig:    "14832ae7",
		Zid:       "uaa",

		RegisteredClaims: jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    jku,
			Subject:   "f62c94ae-2552-411b-9f8e-9ad181c50b40",
			Audience:  []string{"openid", "bosh_cli", "bosh"},
		},
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem := pem.EncodeToMemory(block)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["jku"] = jku
	token.Header["kid"] = "uaa-jwt-key-1"
	ss, err := token.SignedString(privateKey)
	if err != nil {
		zap.L().Panic("unable to write signed string", zap.Error(err))
	}

	return string(publicPem), ss
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
			"Authorization": {fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte("bosh_cli:")))},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(url.Values{
			"grant_type": {"refresh_token"},
		}.Encode()))),
	}
	res, err := http.DefaultClient.Do(&req)
	if err != nil {
		return "", err
	}

	defer func() { _ = res.Body.Close() }()

	var newTokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	err = json.NewDecoder(res.Body).Decode(&newTokens)
	if err != nil {
		return "", err
	}

	err = req.Body.Close()
	if err != nil {
		return "", err
	}

	return newTokens.AccessToken, nil
}
