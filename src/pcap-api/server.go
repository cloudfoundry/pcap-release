package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
)

type Api struct {
	httpServer *http.Server
	config     *Config
	cf         *CfCaptureHandler
}

func (a *Api) handleHealth(response http.ResponseWriter, _ *http.Request) {
	response.WriteHeader(http.StatusOK)
}

func (a *Api) Run() {
	log.Info("Pcap-API starting...")
	a.cf.setup()

	mux := http.NewServeMux()

	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/capture", a.cf.handleCapture)
	mux.HandleFunc("/capture/capture", a.cf.handleCapture)
	log.Info("Starting CLI file Api at root " + a.config.CLIDownloadRoot)
	mux.Handle("/cli/", http.StripPrefix("/cli/", http.FileServer(http.Dir(a.config.CLIDownloadRoot))))

	a.httpServer = &http.Server{
		Addr:    a.config.Listen,
		Handler: mux,
	}

	log.Infof("Listening on %s ...", a.config.Listen)
	if a.config.EnableServerTLS {
		log.Info(a.httpServer.ListenAndServeTLS(a.config.Cert, a.config.Key))
	} else {
		log.Info(a.httpServer.ListenAndServe())
	}
}

func (a *Api) Stop() {
	log.Info("Pcap-API stopping...")
	_ = a.httpServer.Close()
}

func NewApi(c *Config) (*Api, error) {
	if c == nil {
		return nil, fmt.Errorf("config required")
	}

	return &Api{
		config: c,
		cf:     NewCfCaptureHandler(c),
	}, nil
}
