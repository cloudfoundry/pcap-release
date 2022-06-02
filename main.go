package main

import (
	log "github.com/sirupsen/logrus"
	"os"
)

func main() {
	log.SetFormatter(&log.JSONFormatter{TimestampFormat: "2006-01-02 15:04:05.0000"})

	if len(os.Args) > 1 {
		configFile := os.Args[1]
		log.Infof("Loading config from %q\n", configFile)

		config, err := NewConfigFromFile(configFile)

		if err != nil {
			log.Fatal(err)
		}

		lv, err := log.ParseLevel(config.LogLevel)
		if err != nil {
			log.Fatal(err)
		}
		log.SetLevel(lv)

		log.Info("Starting the server...")
		config.NewServer().run()
	} else {
		log.Fatalf("ERROR: No configuration file provided.\nUsage: %s <configfile>", os.Args[0])
	}

}
