package main

import (
	"os"

	"github.com/domdom82/pcap-server-api/config"
	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetFormatter(&log.JSONFormatter{TimestampFormat: "2006-01-02 15:04:05.0000"})

	var cfg *config.Config
	var err error
	if len(os.Args) > 1 {
		configFile := os.Args[1]
		log.Infof("Loading config from %q\n", configFile)

		cfg, err = config.NewConfigFromFile(configFile)

		if err != nil {
			log.Fatal(err)
		}
	} else {
		cfg = &config.DefaultConfig
	}

	lv, err := log.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Fatal(err)
	}
	log.SetLevel(lv)
	log.Info("Starting the Server...")
	srv, err := NewServer(cfg)
	if err != nil {
		log.Fatal(err)
	}
	srv.Run()
}
