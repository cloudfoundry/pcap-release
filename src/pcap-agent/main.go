package main

import (
	"os"

	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetFormatter(&log.JSONFormatter{TimestampFormat: "2006-01-02 15:04:05.0000"})

	var cfg *Config
	var err error
	if len(os.Args) > 1 {
		configFile := os.Args[1]
		log.Infof("Loading config from %q\n", configFile)

		cfg, err = NewConfigFromFile(configFile)

		if err != nil {
			log.Fatal(err)
		}
	} else {
		cfg = &DefaultConfig
	}

	lv, err := log.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Fatal(err)
	}
	log.SetLevel(lv)
	log.Info("Starting the Agent...")
	srv, err := NewAgent(cfg)
	if err != nil {
		log.Fatal(err)
	}
	srv.Run()
}
