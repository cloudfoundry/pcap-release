package main

import (
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type Api struct {
	httpServer *http.Server
	config     *Config
	cf         *CfCaptureHandler
	bosh       *BoshCaptureHandler
}

func (a *Api) handleHealth(response http.ResponseWriter, _ *http.Request) {
	response.WriteHeader(http.StatusOK)
}

func (a *Api) Run() {
	log.Info("Pcap-API starting...")

	mux := http.NewServeMux()

	mux.HandleFunc("/health", a.handleHealth)

	if a.config.CfAPI != "" {
		a.cf.setup()
		mux.HandleFunc("/capture/cf", a.cf.handleCapture)
	}

	if a.config.BoshDirectorAPI != "" {
		a.bosh.setup()
		mux.HandleFunc("/capture/bosh", a.bosh.handleCapture)
	}

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
		bosh:   NewBoshCaptureHandler(c),
	}, nil
}
