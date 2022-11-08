package main

import (
	"os"

	"github.com/cloudfoundry/pcap-release/src/pcap-api"

	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetFormatter(&log.JSONFormatter{TimestampFormat: "2006-01-02 15:04:05.0000"})

	var cfg *api.Config
	var err error
	if len(os.Args) > 1 {
		configFile := os.Args[1]
		log.Infof("Loading config from %q\n", configFile)

		cfg, err = api.NewConfigFromFile(configFile)

		if err != nil {
			log.Fatal(err)
		}
	} else {
		cfg = &api.DefaultConfig
	}

	lv, err := log.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Fatal(err)
	}
	log.SetLevel(lv)
	log.Info("Starting the Api...")
	srv, err := api.NewApi(cfg)
	if err != nil {
		log.Fatal(err)
	}
	srv.Run()
}
