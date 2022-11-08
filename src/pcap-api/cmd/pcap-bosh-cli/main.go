package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/cloudfoundry/pcap-release/src/pcap-api"

	"code.cloudfoundry.org/bytefmt"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

var (
	config boshConfig
	opts   options
	client *http.Client
)

type environment struct {
	AccessToken     string `yaml:"access_token"`
	AccessTokenType string `yaml:"access_token_type"`
	Alias           string `yaml:"alias"`
	CaCert          string `yaml:"ca_cert"`
	RefreshToken    string `yaml:"refresh_token"`
	Url             string `yaml:"url"`
}

type boshConfig struct {
	Environments []environment `json:"environments"`
}

type options struct {
	File            string   `short:"o" long:"file" description:"The output file. Written in binary pcap format." required:"true"`
	PcapApiUrl      string   `short:"u" long:"pcap-api-url" description:"The URL of the PCAP API, e.g. pcap.cf.$LANDSCAPE_DOMAIN" env:"PCAP_API" required:"true"`
	Filter          string   `short:"f" long:"filter" description:"Allows to provide a filter expression in pcap filter format." required:"false"`
	Interface       string   `short:"i" long:"interface" description:"Specifies the network interface to listen on." default:"eth0" required:"false"`
	Type            string   `short:"t" long:"type" description:"Specifies the type of process to capture for the app." default:"web" required:"false"`
	BoshConfig      string   `short:"c" long:"bosh-config" description:"Path to the BOSH config file, used for the UAA Token" default:"${HOME}/.bosh/config" required:"false"`
	BoshEnvironment string   `short:"e" long:"bosh-environment" description:"The BOSH environment to use for retrieving the BOSH UAA token from the BOSH config file" default:"bosh" required:"false"`
	BoshToken       string   `short:"T" long:"token" description:"BOSH UAA Token to use for authentication (instead of BOSH config file)" env:"BOSH_TOKEN" default:"" required:"false"`
	Deployment      string   `short:"d" long:"deployment" description:"The name of the deployment in which you would like to capture." required:"true"`
	InstanceGroups  []string `short:"g" long:"instance-group" description:"The name of an instance group in the deployment in which you would like to capture. Can be defined multiple times." required:"true"`
	InstanceIds     []string `positional-arg-name:"ids" description:"The instance IDs of the deployment to capture." required:"false"`
}

func init() {
	var err error
	defer func() {
		if err != nil {
			log.Fatalf("error: init: %s", err.Error())
		}
	}()

	_, err = flags.ParseArgs(&opts, os.Args[1:])
	if err != nil {
		return
	}

	config, err = readConfig(os.ExpandEnv(opts.BoshConfig))
	if err != nil {
		return
	}

	client = &http.Client{
		Transport: http.DefaultTransport.(*http.Transport).Clone(),
	}

	log.SetLevel(log.DebugLevel)
}

func main() {
	var err error
	defer func() {
		if err != nil {
			log.Fatalf("error: %s", err.Error())
		}
	}()

	if opts.BoshToken == "" {
		opts.BoshToken, err = getToken(config, opts.BoshEnvironment)
		if err != nil {
			return
		}
	}

	status, err := getApiStatus(opts, client)
	if !status.Up {
		err = fmt.Errorf("api not up")
		return
	}
	if !status.Handlers.Bosh {
		err = fmt.Errorf("api server does not support bosh")
		return
	}

	var parameters url.Values = map[string][]string{
		"deployment":  {opts.Deployment},
		"device":      {opts.Interface},
		"filter":      {opts.Filter},
		"instance_id": opts.InstanceIds,
		"group":       opts.InstanceGroups,
	}

	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme:   "https",
			Host:     opts.PcapApiUrl,
			Path:     "/capture/bosh",
			RawQuery: parameters.Encode(),
		},
		Header: map[string][]string{
			"Authorization": {"Bearer " + opts.BoshToken},
		},
	}

	instanceIds := "all"
	if len(opts.InstanceIds) > 0 {
		instanceIds = strings.Join(opts.InstanceIds, ", ")
	}

	fmt.Printf("Capturing traffic of deployment: %s groups: %v instances: %v into file %s ...\n", opts.Deployment, opts.InstanceGroups, instanceIds, opts.File)
	res, err := client.Do(req)
	if err != nil {
		fmt.Printf("Could not receive pcap stream: %s\n", err)
		return
	}
	fmt.Println("foo")

	defer silentClose(res.Body)

	if res.StatusCode != http.StatusOK {
		var msg []byte
		msg, err = io.ReadAll(res.Body)
		if err != nil {
			panic(err.Error())
		}

		err = fmt.Errorf("unexpected status code api: %d (%s)", res.StatusCode, string(msg))
		return
	}

	file, err := os.Create(opts.File)
	if err != nil {
		return
	}

	defer silentClose(file)

	copyWg := &sync.WaitGroup{}
	copyWg.Add(1)
	go func(writer io.Writer, reader io.Reader) {
		written, err := io.CopyBuffer(writer, reader, make([]byte, 1048576)) // 1 Mebibyte
		if err != nil {
			log.Errorf("copy operation stopped: %s", err.Error())
		}
		log.Infof("captured %s", bytefmt.ByteSize(uint64(written)))
		copyWg.Done()
	}(file, res.Body)

	stopProgress := make(chan bool)
	go progress(file, stopProgress)

	log.Debug("registering signal handler for SIGINT")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	log.Debug("waiting for SIGINT to be sent")
	<-sigChan

	log.Debug("received SIGINT, stopping progress")
	stopProgress <- true

	log.Debug("stopping capture by closing response body")
	err = res.Body.Close()

	log.Debug("waiting for copy operation to stop")
	copyWg.Wait()

	log.Debug("syncing file to disk")
	err = file.Sync()
	if err != nil {
		return
	}

	log.Debug("closing file")
	err = file.Close()
	if err != nil {
		return
	}
}

func progress(file *os.File, stop <-chan bool) {
	ticker := time.Tick(time.Second)
	for {
		select {
		case <-ticker:
			info, err := file.Stat()
			if err != nil {
				panic(err.Error())
			}

			fmt.Printf("\033[2K\rWrote %s bytes to disk.", bytefmt.ByteSize(uint64(info.Size())))
		case <-stop:
			return
		}
	}
}

func readConfig(path string) (config boshConfig, err error) {
	configReader, err := os.Open(path)

	err = yaml.NewDecoder(configReader).Decode(&config)
	if err != nil {
		return boshConfig{}, fmt.Errorf("read config: %w", err)
	}

	return config, nil
}

func getToken(config boshConfig, boshEnv string) (string, error) {
	for _, e := range config.Environments {
		if e.Alias == boshEnv {
			return e.AccessToken, nil
		}
	}

	return "", fmt.Errorf("get token: environment '%s' not found", boshEnv)
}

func getApiStatus(opts options, client *http.Client) (status api.Status, err error) {
	res, err := client.Do(&http.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme: "https",
			Host:   opts.PcapApiUrl,
			Path:   "/health",
		},
		Header: map[string][]string{
			"Authorization": {"Bearer " + opts.BoshToken},
		},
	})
	if err != nil {
		return api.Status{}, fmt.Errorf("get api status: %w", err)
	}

	defer silentClose(res.Body)

	err = json.NewDecoder(res.Body).Decode(&status)
	if err != nil {
		return api.Status{}, fmt.Errorf("get api status: %w", err)
	}

	return status, nil
}

// silentClose ignores errors returned when closing the io.Closer.
func silentClose(closer io.Closer) {
	_ = closer.Close()
}
