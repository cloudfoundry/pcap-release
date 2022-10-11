package main

import (
	"code.cloudfoundry.org/bytefmt"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/cloudfoundry/pcap-release/pcap-api/api"
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

func main() {

	var opts struct {
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

	_, err := flags.ParseArgs(&opts, os.Args[1:])

	if err != nil {
		panic(err)
	}

	if opts.BoshToken == "" {
		boshConfigPath := os.ExpandEnv(opts.BoshConfig)
		yamlFile, err := os.ReadFile(boshConfigPath)

		if err != nil {
			log.Printf("error while reading yaml file: %v ", err)

			return
		}

		bc := boshConfig{}

		err = yaml.Unmarshal(yamlFile, &bc)
		if err != nil {
			log.Printf("error while parsing yaml file %s: %v ", boshConfigPath, err)
			return
		}

		for _, e := range bc.Environments {
			if e.Alias == opts.BoshEnvironment {
				opts.BoshToken = e.AccessToken
			}
		}
	}

	tp := http.DefaultTransport.(*http.Transport).Clone()
	tp.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // TODO remove before putting into production
	httpClient := &http.Client{Transport: tp}

	res, err := httpClient.Get(fmt.Sprintf("%s/health", opts.PcapApiUrl))
	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	status := &api.Status{}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Errorf("could not read status: %v", err)
		return
	}

	err = json.Unmarshal(body, status)

	if err != nil {
		log.Errorf("could not read status: %v", err)
		return
	}

	if !status.Handlers.Bosh {
		log.Fatalf("The PCAP endpoint does not support BOSH capturing")
	}

	urlStr := fmt.Sprintf("%s/capture/bosh?deployment=%s&device=%s&filter=%s", opts.PcapApiUrl, opts.Deployment, opts.Interface, opts.Filter)
	log.Infof("Calling: %s", urlStr)
	for _, index := range opts.InstanceIds {
		urlStr = fmt.Sprintf("%s&instance_id=%s", urlStr, index)
	}
	for _, group := range opts.InstanceGroups {
		urlStr = fmt.Sprintf("%s&group=%s", urlStr, group)
	}

	reqURL, err := url.Parse(urlStr)

	if err != nil {
		fmt.Printf("Could not parse URL: %s\n", err)
		return
	}

	req := &http.Request{
		Method: "GET",
		URL:    reqURL,
		Header: map[string][]string{
			"Authorization": {"Bearer " + opts.BoshToken},
		},
	}

	instanceIds := "all"
	if len(opts.InstanceIds) > 0 {
		instanceIds = strings.Join(opts.InstanceIds, ", ")
	}

	fmt.Printf("Capturing traffic of deployment: %s groups: %v instances: %v into file %s ...\n", opts.Deployment, opts.InstanceGroups, instanceIds, opts.File)
	resp, err := httpClient.Do(req)

	if err != nil {
		fmt.Printf("Could not receive pcap stream: %s\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Unexpected status code from pcap api server: %d\n", resp.StatusCode)
		msg, _ := io.ReadAll(resp.Body)
		fmt.Printf("Details: %s\n", msg)
		return
	}

	file, err := os.Create(opts.File)
	defer file.Close()

	if err != nil {
		fmt.Printf("Could not open %s for writing: %s\n", opts.File, err)
		return
	}
	totalBytes := uint64(0)
	updateProgress := func(nBytes int) {
		totalBytes += uint64(nBytes)
		fmt.Printf("\033[2K\rRead %d bytes from stream (%s total)", nBytes, bytefmt.ByteSize(totalBytes))
	}
	updateProgress(0)
	for {
		buffer := make([]byte, 4096)
		n, err := resp.Body.Read(buffer)
		updateProgress(n)
		if n > 0 {
			file.Write(buffer[:n])
		}
		if err != nil {
			handleIOError(err)
			return
		}
	}
}

func handleIOError(err error) {
	if errors.Is(err, io.EOF) {
		fmt.Println("Done.")
	} else {
		fmt.Printf("Error during capture: %s\n", err)
	}
}
