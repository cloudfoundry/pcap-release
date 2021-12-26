package main

import (
	log "github.com/sirupsen/logrus"
	"net/http"
)

type server struct {
	config *Config
}

func (s *server) handleCapture(response http.ResponseWriter, request *http.Request) {

	if request.Method != http.MethodGet {
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	instanceId := request.URL.Query().Get("instanceid")
	//filter := request.URL.Query().Get("filter")

	if instanceId == "" {
		response.WriteHeader(http.StatusBadRequest)
		//TODO: add some nice error message
		return
	}

}

func (s *server) run() {

	mux := http.NewServeMux()

	mux.HandleFunc("/capture", s.handleCapture)

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr:    s.config.Listen,
		Handler: mux,
	}

	// Listen to HTTPS connections with the server certificate and wait
	log.Fatal(server.ListenAndServeTLS(s.config.Cert, s.config.Key))

}
