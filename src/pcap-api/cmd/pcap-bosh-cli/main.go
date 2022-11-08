package main

import (
	"bytes"
	"encoding/base64"
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
	"github.com/cloudfoundry/pcap-release/src/pcap-api/bosh"
	"gopkg.in/yaml.v3"

	"code.cloudfoundry.org/bytefmt"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
)

var (
	config = &bosh.Config{}
	opts   options
	client *http.Client
)

type boshToken struct {
	scheme  string
	access  string
	refresh string
	uaaUrl  *url.URL
}

func newBoshToken(e bosh.Environment) (*boshToken, error) {
	director, err := url.Parse(e.Url)
	if err != nil {
		return nil, err
	}

	res, err := client.Do(&http.Request{
		Method: http.MethodGet,
		URL: &url.URL{
			Scheme: director.Scheme,
			Host:   director.Host,
			Path:   "/info",
		},
		Header: http.Header{
			"Accept": {"application/json"},
		},
	})
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d", res.StatusCode)
	}

	var info bosh.Info
	err = json.NewDecoder(res.Body).Decode(&info)
	if err != nil {
		return nil, err
	}

	uaaUrl, err := url.Parse(info.UserAuthentication.Options.Url)
	if err != nil {
		return nil, err
	}

	return &boshToken{
		scheme:  e.AccessTokenType,
		access:  e.AccessToken,
		refresh: e.RefreshToken,
		uaaUrl:  uaaUrl,
	}, nil
}

func (t *boshToken) refreshAccess() error {
	fmt.Println(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {t.refresh},
	}.Encode())
	req := http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: t.uaaUrl.Scheme,
			Host:   t.uaaUrl.Host,
			Path:   "/oauth/token",
		},
		Header: http.Header{
			"Accept":        {"application/json"},
			"Content-Type":  {"application/x-www-form-urlencoded"},
			"Authorization": {fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte("bosh_cli:")))}, // TODO: the client name is also written in the token
		},
		Body: io.NopCloser(bytes.NewReader([]byte(url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {t.refresh},
		}.Encode()))),
	}
	res, err := client.Do(&req)
	if err != nil {
		return err
	}

	var newTokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	err = json.NewDecoder(res.Body).Decode(&newTokens)
	if err != nil {
		return err
	}

	t.refresh = newTokens.RefreshToken
	t.scheme = newTokens.TokenType
	t.access = newTokens.AccessToken

	return nil
}

type options struct {
	File            string   `short:"o" long:"file" description:"The output file. Written in binary pcap format." required:"true"`
	PcapApiUrl      string   `short:"u" long:"pcap-api-url" description:"The URL of the PCAP API, e.g. pcap.cf.$LANDSCAPE_DOMAIN" env:"PCAP_API" required:"true"`
	Filter          string   `short:"f" long:"filter" description:"Allows to provide a filter expression in pcap filter format." required:"false"`
	Interface       string   `short:"i" long:"interface" description:"Specifies the network interface to listen on." default:"eth0" required:"false"`
	Type            string   `short:"t" long:"type" description:"Specifies the type of process to capture for the app." default:"web" required:"false"`
	BoshConfig      string   `short:"c" long:"bosh-config" description:"Path to the BOSH config file, used for the UAA Token" default:"${HOME}/.bosh/config" required:"false"`
	BoshEnvironment string   `short:"e" long:"bosh-environment" description:"The BOSH environment to use for retrieving the BOSH UAA token from the BOSH config file" default:"bosh" required:"false"`
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

	opts.BoshConfig = os.ExpandEnv(opts.BoshConfig)
	configReader, err := os.Open(opts.BoshConfig)
	config = &bosh.Config{}
	err = yaml.NewDecoder(configReader).Decode(config)
	if err != nil {
		return
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig.InsecureSkipVerify = true

	client = &http.Client{
		Transport: transport,
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

	token, err := getToken(config, opts.BoshEnvironment)
	if err != nil {
		return
	}

	err = token.refreshAccess()
	if err != nil {
		return
	}

	for i, e := range config.Environments {
		if e.Alias == opts.BoshEnvironment {
			config.Environments[i].RefreshToken = token.refresh
			config.Environments[i].AccessToken = token.access
			config.Environments[i].AccessTokenType = token.scheme
			break
		}
	}

	configWriter, err := os.Create(opts.BoshConfig)
	if err != nil {
		return
	}

	err = yaml.NewEncoder(configWriter).Encode(config)
	if err != nil {
		return
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
			"Authorization": {fmt.Sprintf("Bearer %s", token.access)}, // TODO: bosh requires an upper-case version of `bearer` even though it is case insensitive, but there is a access token type which is lower-case...
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

func getToken(config *bosh.Config, boshEnv string) (*boshToken, error) {
	for _, e := range config.Environments {
		if e.Alias == boshEnv {
			return newBoshToken(e)
		}
	}

	return nil, fmt.Errorf("get token: environment '%s' not found", boshEnv)
}

func getApiStatus(opts options, client *http.Client) (status api.Status, err error) {
	res, err := client.Do(&http.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme: "https",
			Host:   opts.PcapApiUrl,
			Path:   "/health",
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
