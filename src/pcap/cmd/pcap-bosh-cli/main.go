package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/cloudfoundry/pcap-release/src/pcap/bosh"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
)

var (
	config      = &bosh.Config{}
	opts        options
	client      *http.Client
	environment bosh.Environment
)

type boshToken struct {
	scheme  string
	access  string
	refresh string
	uaaURL  *url.URL
}

type options struct {
	File            string   `short:"o" long:"file" description:"The output file. Written in binary pcap format." required:"true"`
	PcapAPIURL      string   `short:"u" long:"pcap-api-url" description:"The URL of the PCAP API, e.g. pcap.cf.$LANDSCAPE_DOMAIN" env:"PCAP_API" required:"true"`
	Filter          string   `short:"f" long:"filter" description:"Allows to provide a filter expression in pcap filter format." required:"false"`
	Interface       string   `short:"i" long:"interface" description:"Specifies the network interface to listen on." default:"eth0" required:"false"`
	Type            string   `short:"t" long:"type" description:"Specifies the type of process to capture for the app." default:"web" required:"false"`
	BoshConfig      string   `short:"c" long:"bosh-config" description:"Path to the BOSH config file, used for the UAA Token" default:"${HOME}/.bosh/config" required:"false"`
	BoshEnvironment string   `short:"e" long:"bosh-environment" description:"The BOSH environment to use for retrieving the BOSH UAA token from the BOSH config file" default:"bosh" required:"false"`
	Deployment      string   `short:"d" long:"deployment" description:"The name of the deployment in which you would like to capture." required:"true"`
	InstanceGroups  []string `short:"g" long:"instance-group" description:"The name of an instance group in the deployment in which you would like to capture. Can be defined multiple times." required:"true"`
	InstanceIds     []string `positional-arg-name:"ids" description:"The instance IDs of the deployment to capture." required:"false"`
}

func tempInit() {
	var err error

	// TODO: do not use CommonConfig
	var cliConfig Config
	cliConfig = DefaultConfig
	cliConfig.validate()

	log.Debug("initializing pcap-bosh-cli", zap.Int64("compatibilityLevel", pcap.CompatibilityLevel))

	_, err = flags.ParseArgs(&opts, os.Args[1:])
	if err != nil {
		log.Fatal("could not parse the provided arguments", zap.Error(err))
	}

	opts.BoshConfig = os.ExpandEnv(opts.BoshConfig)
	configReader, err := os.Open(opts.BoshConfig)
	if err != nil {
		log.Fatalf("could not open %v: %v", opts.BoshConfig, err.Error())
	}
	config = &bosh.Config{}
	err = yaml.NewDecoder(configReader).Decode(config)
	if err != nil {
		log.Fatal("could not parse the provided bosh-config", zap.Error(err), zap.String("bosh-config-path", opts.BoshConfig))
	}

	// TODO: extract to method
	environment, err = getEnvironment(opts.BoshEnvironment)
	if err != nil {
		log.Fatal("could not get environment config", zap.Error(err), zap.String("environment", opts.BoshEnvironment))
	}

	environmentURL, err := url.Parse(environment.Url)
	if err != nil {
		log.Fatalf("error parsing environment url: %v", environment.Url)
	}
	if environmentURL.Scheme == "https" {
		boshCA := x509.NewCertPool()
		ok := boshCA.AppendCertsFromPEM([]byte(environment.CaCert))
		if !ok {
			log.Fatalf("could not add BOSH Director CA from %v, adding to the cert pool failed.", opts.BoshConfig)
		}

		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig.RootCAs = boshCA

		client = &http.Client{
			Transport: transport,
		}
	} else {
		client = http.DefaultClient
	}
}

func main() {
	// TODO Split up in multiple methods
	tempInit()

	apiURL, err := parseAPIURL(opts.PcapAPIURL)
	if err != nil {
		log.Fatal(err.Error()) // TODO
	}

	log := zap.L()
	log.Info("done with init")

	token, err := updateTokens()
	if err != nil {
		log.Fatal(err.Error()) // TODO
	}

	client, err := pcap.NewClient(opts.File, apiURL, log)
	if err != nil {
		log.Fatal(err.Error()) // TODO
		return
	}

	endpointRequest := &pcap.EndpointRequest{
		Request: &pcap.EndpointRequest_Bosh{
			Bosh: &pcap.BoshRequest{
				Token:      token,
				Deployment: opts.Deployment,
				Groups:     opts.InstanceGroups,
			},
		},
	}

	captureOptions := &pcap.CaptureOptions{
		Device:  opts.Interface,
		Filter:  opts.Filter,
		SnapLen: 65_000, // TODO: get from config or parameters
	}

	ctx := context.Background()
	ctx, cancel := pcap.WithCancelCause(ctx)
	setupContextCancel(cancel)

	err = client.HandleRequest(endpointRequest, captureOptions, ctx, cancel)
	if err != nil {
		log.Fatal("encountered error during request handling: %s", zap.Error(err))
	}

	err = pcap.Cause(ctx)
	if err != nil {
		if status.Code(err) == codes.OK {
			log.Info("finished successfully")
			return
		}
		log.Fatal("finished with error ", zap.Error(err))
	}
}

func setupContextCancel(cancel pcap.CancelCauseFunc) {
	log.Debug("registering signal handler for SIGINT")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	go func() {
		log.Debug("waiting for SIGINT to be sent")
		<-sigChan

		log.Debug("received SIGINT, stopping progress")
		//cancelCause := pcap.errorf() // TODO: make public so we can use the status to accept this as a successful exit
		cancelCause := fmt.Errorf("client stop")
		cancel(cancelCause)
	}()
}

func updateTokens() (string, error) { //TODO: logging
	token, err := newBoshToken(environment)
	if err != nil {
		return "", err
	}

	err = token.refreshAccess()
	if err != nil {
		return "", err
	}

	environment.RefreshToken = token.refresh
	environment.AccessToken = token.access
	environment.AccessTokenType = token.scheme

	configWriter, err := os.Create(opts.BoshConfig)
	if err != nil {
		return "", err
	}

	err = yaml.NewEncoder(configWriter).Encode(config)
	if err != nil {
		return "", err
	}

	return token.access, nil
}

func newBoshToken(e bosh.Environment) (*boshToken, error) { //TODO: logging
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
		uaaURL:  uaaUrl,
	}, nil
}

func (t *boshToken) refreshAccess() error { //TODO: logging
	req := http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: t.uaaURL.Scheme,
			Host:   t.uaaURL.Host,
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

func getEnvironment(alias string) (bosh.Environment, error) {
	for _, environment := range config.Environments {
		if environment.Alias == opts.BoshEnvironment {
			return environment, nil
		}
	}
	return bosh.Environment{}, fmt.Errorf("could not find environment %v", alias)
}

func parseAPIURL(urlString string) (*url.URL, error) {
	// check if urlString contains a scheme
	re := regexp.MustCompile(`^(\w+://)`) //
	if re.MatchString(urlString) {
		if strings.HasPrefix(urlString, "http") { // http & https are the only supported protocols
			return url.Parse(urlString)
		}
		return nil, fmt.Errorf("unsupported pcap-api scheme: %s", urlString)
	}

	// url has no scheme: we'll default to https
	return &url.URL{Scheme: "https", Host: urlString}, nil
}
