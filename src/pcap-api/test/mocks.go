package test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"text/template"

	log "github.com/sirupsen/logrus"
)

func MockBoshDirectorAPI(responses map[string]string) *httptest.Server {

	mux := http.NewServeMux()
	mux.HandleFunc("/info", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Write([]byte("{}"))
	})

	ts := httptest.NewServer(mux)

	return ts
}

func MockCfAPI(responses map[string]string) *httptest.Server {
	json := `
{
  "links": {
    "self": {
      "href": "{{.BaseURL}}"
    },
    "cloud_controller_v3": {
      "href": "{{.CCV3URL}}",
      "meta": {
        "version": "3.115.0"
      }
    },
    "uaa": {
      "href": "{{.UaaURL}}"
    }
  }
}`
	type CfApiMock struct {
		BaseURL, CCV3URL, UaaURL string
	}
	var cfapi CfApiMock
	responseTemplate := template.Must(template.New("cfapi").Parse(json))

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		err := responseTemplate.Execute(writer, cfapi)
		if err != nil {
			panic(err)
		}
	})

	mux.HandleFunc("/v3/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")

		response := responses[request.URL.Path]
		if response == "" {
			writer.WriteHeader(http.StatusNotFound)

			return
		}
		writer.Write([]byte(response))
	})

	ts := httptest.NewServer(mux)
	cfapi = CfApiMock{
		BaseURL: ts.URL,
		CCV3URL: ts.URL + "/v3",
		UaaURL:  ts.URL + "/uaa",
	}

	return ts
}

type MockPcapAgent struct {
	*httptest.Server
	Host string
	Port string
}

func NewMockPcapAgent(responses map[string]string) *MockPcapAgent {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		response := responses[request.URL.Path+"?"+request.URL.RawQuery]
		if response == "" {
			writer.WriteHeader(http.StatusNotFound)

			return
		}
		file, err := os.Open(response)
		if err != nil {
			panic(err)
		}
		nbytes, err := io.Copy(writer, file)
		if err != nil {
			panic(err)
		}
		log.Infof("wrote %s with %d bytes", response, nbytes)
	})

	mockup := MockPcapAgent{Server: httptest.NewTLSServer(mux)}

	pcapAgentUrl, _ := url.Parse(mockup.URL)
	mockup.Host = pcapAgentUrl.Hostname()
	mockup.Port = pcapAgentUrl.Port()

	return &mockup
}
