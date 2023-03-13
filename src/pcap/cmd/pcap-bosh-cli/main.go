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
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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
	config         *bosh.Config
	opts           options
	client         *http.Client
	environment    bosh.Environment
	logger         *zap.Logger
	atomicLogLevel zap.AtomicLevel
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
	Verbose         []bool   `short:"v" long:"verbose" description:"Show verbose debug information"`
}

func readBoshConfig() {
	var err error

	// Read Bosh Config from Config File
	opts.BoshConfig = os.ExpandEnv(opts.BoshConfig)
	configReader, err := os.Open(opts.BoshConfig)
	if err != nil {
		logger.Fatal("could not open Bosh Config", zap.Any("bosh-config", opts.BoshConfig), zap.Error(err))
	}
	config = &bosh.Config{}
	err = yaml.NewDecoder(configReader).Decode(config)
	if err != nil {
		logger.Fatal("could not parse the provided bosh-config", zap.Error(err), zap.String("bosh-config-path", opts.BoshConfig))
	}
	logger.Debug("read bosh-config", zap.Any("bosh-config", config))
}
func setupBoshConnection() {
	var err error
	environment = getEnvironment()

	environmentURL, err := url.Parse(environment.Url)
	if err != nil {
		logger.Fatal("error parsing environment url", zap.String("environment-url", environment.Url))
	}

	if environmentURL.Scheme == "https" {
		logger.Info("using TLS-encrypted connection to bosh-director", zap.String("bosh-director-url", environmentURL.String()))
		boshCA := x509.NewCertPool()
		ok := boshCA.AppendCertsFromPEM([]byte(environment.CaCert))
		if !ok {
			logger.Fatal("could not add BOSH Director CA from bosh-config, adding to the cert pool failed.", zap.Any("bosh-config", opts.BoshConfig))
		}

		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig.RootCAs = boshCA

		client = &http.Client{
			Transport: transport,
		}
	} else {
		logger.Info("using unencrypted connection to bosh-director", zap.String("bosh-director-url", environmentURL.String()))
		client = http.DefaultClient
	}
}

func main() {
	var err error

	setupLogging()

	_, err = flags.ParseArgs(&opts, os.Args[1:])
	if err != nil {
		logger.Fatal("could not parse the provided arguments", zap.Error(err))
	}

	setLogLevel(opts.Verbose) // we cannot log to Debug before this point

	apiURL := parseAPIURL(opts.PcapAPIURL)

	logger.Debug("pcap-bosh-cli initialized", zap.Int64("compatibilityLevel", pcap.CompatibilityLevel))

	readBoshConfig()
	setupBoshConnection()

	token := updateTokens()

	client, err := pcap.NewClient(opts.File, apiURL, logger)
	if err != nil {
		logger.Fatal(err.Error()) // TODO
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
		logger.Fatal("encountered error during request handling: %s", zap.Error(err))
	}

	err = pcap.Cause(ctx)
	if err != nil {
		if status.Code(err) == codes.OK {
			logger.Info("finished successfully")
			return
		}
		logger.Fatal("finished with error ", zap.Error(err))
	}
}

func setupLogging() {
	atomicLogLevel = zap.NewAtomicLevelAt(zap.WarnLevel)
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	zapConfig := zap.Config{
		Level:             atomicLogLevel,
		DisableCaller:     true,
		DisableStacktrace: true,
		Encoding:          "console",
		EncoderConfig:     encoderConfig,
		OutputPaths:       []string{"stderr"},
		ErrorOutputPaths:  []string{"stderr"},
	}
	logger = zap.Must(zapConfig.Build())
	zap.ReplaceGlobals(logger)
	logger.Debug("successfully set up logger")
}

func setLogLevel(verbose []bool) {
	var logLevel zapcore.Level
	switch len(verbose) {
	case 0:
		logLevel = zapcore.WarnLevel
	case 1:
		logLevel = zapcore.InfoLevel
	default: // if more than one -v is given as argument
		logLevel = zapcore.DebugLevel
	}

	atomicLogLevel.SetLevel(logLevel)

	logger.Debug("set log-level", zap.String("log-level", logLevel.String()))
}

func setupContextCancel(cancel pcap.CancelCauseFunc) {
	logger.Debug("registering signal handler for SIGINT")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	go func() {
		logger.Debug("waiting for SIGINT to be sent")
		<-sigChan

		logger.Debug("received SIGINT, stopping progress")
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

func getEnvironment() bosh.Environment {
	for _, environment := range config.Environments {
		if environment.Alias == opts.BoshEnvironment {
			logger.Debug("found bosh-environment", zap.String("environment-alias", environment.Alias))
			return environment
		}
	}
	logger.Fatal("could not find bosh-environment in config", zap.String("environment-alias", opts.BoshEnvironment))
	return bosh.Environment{}
}

func parseAPIURL(urlString string) *url.URL {
	// check if urlString contains a scheme
	re := regexp.MustCompile(`^(\w+://)`) //
	if re.MatchString(urlString) {
		if strings.HasPrefix(urlString, "http") { // http & https are the only supported protocols
			logger.Debug("pcap-api URL contains http/https scheme")
			url, err := url.Parse(urlString)
			if err != nil {
				logger.Fatal("could not parse pcap-api URL", zap.String("pcap-api URl", urlString), zap.Error(err))
			}
			return url
		}
		logger.Fatal("unsupported pcap-api URL scheme", zap.String("pcap-api URl", urlString))
	}
	logger.Info("pcap-api URL does not contain scheme. Defaulting to HTTPS.", zap.String("pcap-api URl", urlString))
	return &url.URL{Scheme: "https", Host: urlString}
}
