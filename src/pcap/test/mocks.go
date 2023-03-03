package test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"text/template"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func MockjwtAPI() (*httptest.Server, string) {

	type JwtAPIMock struct {
		UAAUrl string
	}

	var JwtApi JwtAPIMock

	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	jku := ts.URL + "/token_keys"

	publicPemKey, token := verifyJWTTokenMock(jku)

	// the response body must not contain any linebreaks or json parsing will fail
	re := regexp.MustCompile(`\r?\n`)
	publicPemKeyNoLineBreak := re.ReplaceAllString(publicPemKey, "\\n")

	json := fmt.Sprintf(`{"keys":[{"kty": "RSA","e": "AQAB","use": "sig","kid": "uaa-jwt-key-1","alg": "RS256","value": "%v","n": ""}]}`, publicPemKeyNoLineBreak)

	mux.HandleFunc("/token_keys", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")

		writer.Write([]byte(json))
	})

	mux.HandleFunc("/oauth/token", func(writer http.ResponseWriter, request *http.Request) {
		response := fmt.Sprintf(`{"access_token": "%v","refresh_token": "%v","token_type": "bearer"}`, token, token)
		writer.Write([]byte(response))
	})

	JwtApi.UAAUrl = ts.URL

	return ts, token
}

func MockBoshDirectorAPI(responses map[string]string, url string) *httptest.Server {
	json := `{
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
			"url": "{{.URL}}",
			"urls": [
			  "{{.URL}}"
			]
		  }
		}
	}`

	type BoshApiMock struct {
		URL string
	}
	var boshapi BoshApiMock

	responseTemplate := template.Must(template.New("boshapi").Parse(json))

	mux := http.NewServeMux()
	mux.HandleFunc("/info", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		err := responseTemplate.Execute(writer, boshapi)
		if err != nil {
			panic(err)
		}
	})

	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")

		response, ok := responses[request.URL.Path]
		if !ok {
			writer.WriteHeader(http.StatusNotFound)

			return
		}

		writer.Write([]byte(response))
	})

	ts := httptest.NewServer(mux)
	boshapi.URL = url

	return ts
}

func verifyJWTTokenMock(jku string) (string, string) {

	type payload struct {
		Scope     []string  `json:"scope"`
		ClientId  string    `json:"client_id"`
		Cid       string    `json:"cid"`
		Azp       string    `json:"azp"`
		GrantType string    `json:"grant_type"`
		UserId    string    `json:"user_id"`
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

		Scope: []string{"openid",
			"bosh.admin"},
		ClientId:  "bosh_cli",
		Cid:       "bosh_cli",
		Azp:       "bosh_cli",
		GrantType: "password",
		UserId:    "f62c94ae-2552-411b-9f8e-9ad181c50b40",
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
	publickeybytes, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publickeybytes,
	}
	publicPem := pem.EncodeToMemory(block)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["jku"] = jku
	token.Header["kid"] = "uaa-jwt-key-1"
	ss, err := token.SignedString(privateKey)
	//fmt.Printf("%v %v", ss, err)

	return string(publicPem), ss
}

//TODO: unused code (so far) - remove?

//func MockCfAPI(responses map[string]string) *httptest.Server {
//	json := `
//{
//  "links": {
//    "self": {
//      "href": "{{.BaseURL}}"
//    },
//    "cloud_controller_v3": {
//      "href": "{{.CCV3URL}}",
//      "meta": {
//        "version": "3.115.0"
//      }
//    },
//    "uaa": {
//      "href": "{{.UaaURL}}"
//    }
//  }
//}`
//	type CfApiMock struct {
//		BaseURL, CCV3URL, UaaURL string
//	}
//	var cfapi CfApiMock
//	responseTemplate := template.Must(template.New("cfapi").Parse(json))
//
//	mux := http.NewServeMux()
//
//	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
//		writer.Header().Set("Content-Type", "application/json")
//		err := responseTemplate.Execute(writer, cfapi)
//		if err != nil {
//			panic(err)
//		}
//	})
//
//	mux.HandleFunc("/v3/", func(writer http.ResponseWriter, request *http.Request) {
//		writer.Header().Set("Content-Type", "application/json")
//
//		response := responses[request.URL.Path]
//		if response == "" {
//			writer.WriteHeader(http.StatusNotFound)
//
//			return
//		}
//		writer.Write([]byte(response))
//	})
//
//	ts := httptest.NewServer(mux)
//	cfapi = CfApiMock{
//		BaseURL: ts.URL,
//		CCV3URL: ts.URL + "/v3",
//		UaaURL:  ts.URL + "/uaa",
//	}
//
//	return ts
//}
//
//type MockPcapAgent struct {
//	*httptest.Server
//	Host string
//	Port string
//}
//
//func NewMockPcapAgent(responses map[string]string) *MockPcapAgent {
//	mux := http.NewServeMux()
//	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
//		response := responses[request.URL.Path+"?"+request.URL.RawQuery]
//		if response == "" {
//			writer.WriteHeader(http.StatusNotFound)
//
//			return
//		}
//		file, err := os.Open(response)
//		if err != nil {
//			panic(err)
//		}
//		nbytes, err := io.Copy(writer, file)
//		if err != nil {
//			panic(err)
//		}
//		log.Infof("wrote %s with %d bytes", response, nbytes)
//	})
//
//	mockup := MockPcapAgent{Server: httptest.NewTLSServer(mux)}
//
//	pcapAgentUrl, _ := url.Parse(mockup.URL)
//	mockup.Host = pcapAgentUrl.Hostname()
//	mockup.Port = pcapAgentUrl.Port()
//
//	return &mockup
//}
