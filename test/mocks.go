package test

import (
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"text/template"
)

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

type MockPcapServer struct {
	*httptest.Server
	Host string
	Port string
}

func NewMockPcapServer(responses map[string]string) *MockPcapServer {
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

	mockup := MockPcapServer{Server: httptest.NewTLSServer(mux)}

	pcapServerURL, _ := url.Parse(mockup.URL)
	mockup.Host = pcapServerURL.Hostname()
	mockup.Port = pcapServerURL.Port()

	return &mockup
}
