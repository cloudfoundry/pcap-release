package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"time"

	"github.com/jessevdk/go-flags"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"

	"github.com/cloudfoundry/pcap-release/src/pcap"
)

var (
	logger         *zap.Logger
	atomicLogLevel zap.AtomicLevel
)

type options struct {
	File               string   `short:"o" long:"file" description:"The output file. Written in binary pcap format." required:"true"`
	ForceOverwriteFile bool     `short:"F" long:"force-overwrite-output-file" description:"Overwrites the output file if it already exists."`
	PcapAPIURL         string   `short:"u" long:"pcap-api-url" description:"The URL of the PCAP API, e.g. pcap.cf.$LANDSCAPE_DOMAIN" env:"PCAP_API" required:"true"`
	Filter             string   `short:"f" long:"filter" description:"Allows to provide a filter expression in pcap filter format." required:"false"`
	Interface          string   `short:"i" long:"interface" description:"Specifies the network interface to listen on." default:"eth0" required:"false"`
	Type               string   `short:"t" long:"type" description:"Specifies the type of process to capture for the app." default:"web" required:"false"`
	BoshConfigFilename string   `short:"c" long:"bosh-config" description:"Path to the BOSH config file, used for the UAA Token" default:"${HOME}/.bosh/config" required:"false"`
	BoshEnvironment    string   `short:"e" long:"bosh-environment" description:"The BOSH environment to use for retrieving the BOSH UAA token from the BOSH config file" default:"bosh" required:"false"`
	Deployment         string   `short:"d" long:"deployment" description:"The name of the deployment in which you would like to capture." required:"true"`
	InstanceGroups     []string `short:"g" long:"instance-group" description:"The name of an instance group in the deployment in which you would like to capture. Can be defined multiple times." required:"true"`
	InstanceIds        []string `positional-arg-name:"ids" description:"The instance IDs of the deployment to capture." required:"false"`
	Verbose            bool     `short:"v" long:"verbose" description:"Show verbose debug information"`
	Quiet              bool     `short:"q" long:"quiet" description:"Show only warnings and errors"`
}

// init sets up the zap.Logger. Currently outputs to stderr in Console format.
func init() {
	atomicLogLevel = zap.NewAtomicLevelAt(zap.InfoLevel)
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	outputPaths := []string{"stderr"} //TODO: make configurable?
	zapConfig := zap.Config{
		Level:             atomicLogLevel,
		DisableCaller:     true,
		DisableStacktrace: true,
		Encoding:          "console",
		EncoderConfig:     encoderConfig,
		OutputPaths:       outputPaths,
		ErrorOutputPaths:  outputPaths,
	}
	logger = zap.Must(zapConfig.Build())
	zap.ReplaceGlobals(logger)
	logger.Debug("successfully set up logger", zap.Strings("output-paths", outputPaths))
}

func main() {
	var (
		err  error
		opts options
	)

	defer func() {
		if err != nil {
			//logger.Error("execution failed", zap.Error(err))
			logger.Error(err.Error())
			os.Exit(1)
		}
	}()

	// Parse command-line arguments
	_, err = flags.Parse(&opts)
	if err != nil {
		err = fmt.Errorf("could not parse the provided arguments %w", err)
		return
	}

	setLogLevel(opts.Verbose, opts.Quiet) // we cannot log to Debug before this point

	logger.Debug("pcap-bosh-cli initialized", zap.Int64("compatibilityLevel", pcap.CompatibilityLevel))

	err = checkOutputFile(opts.File, opts.ForceOverwriteFile) // TODO: we risk deleting a valid previous capture-file if "-f" is used and the capture fails. to prevent this, we'd have to pass ForceOverwriteFile to the client. Worth it?
	if err != nil {
		return
	}

	// update bosh tokens/config
	apiURL, err := parseAPIURL(urlWithScheme(opts.PcapAPIURL))
	if err != nil {
		return
	}
	boshConfig, err := configFromFile(opts.BoshConfigFilename)
	if err != nil {
		return
	}
	environment, err := getEnvironment(opts.BoshEnvironment, boshConfig)
	if err != nil {
		return
	}
	err = environment.UpdateTokens()
	if err != nil {
		return
	}
	err = writeBoshConfig(boshConfig, opts.BoshConfigFilename)
	if err != nil {
		return
	}

	logger.Debug("bosh-config and tokens successfully updated")

	// set up pcap-client/pcap-api connection
	client, err := pcap.NewClient(opts.File, logger)
	if err != nil {
		err = fmt.Errorf("could not set up pcap-client %w", err)
		return
	}
	err = client.ConnectToAPI(apiURL)
	if err != nil {
		err = fmt.Errorf("could not connect to pcap-api %w", err)
		return
	}
	err = checkAPIHealth(client, environment.Alias)
	if err != nil {
		return
	}

	logger.Debug("pcap-client successfully initialized and connected to pcap-api")

	// set up capture request
	ctx := context.Background()
	ctx, cancel := pcap.WithCancelCause(ctx)
	setupContextCancel(client)
	endpointRequest := createEndpointRequest(environment.AccessToken, opts.Deployment, opts.InstanceGroups, environment.Alias)
	captureOptions := createCaptureOptions(opts.Interface, opts.Filter, 65_000) // TODO: get snaplen from config or parameters

	// perform capture request
	err = client.HandleRequest(ctx, endpointRequest, captureOptions, cancel)
	if err != nil {
		err = fmt.Errorf("encountered error during request handling: %w", err)
		return
	}

	// handle results of capture request
	cause := pcap.Cause(ctx)
	if cause != nil && !errors.Is(cause, context.Canceled) {
		err = fmt.Errorf("finished with error %w", cause)
		return
	}
	logger.Info("capture finished successfully")
}

// checkOutputFile checks if the specified output-file already exists.
// If it does exist and forceOverwriteFile is specified, it will be deleted.
// If it doesn't exist and the parent-directory is invalid an error is returned.
func checkOutputFile(file string, forceOverwriteFile bool) error {
	// Check if the file already exists
	_, err := os.Stat(file)
	if err == nil { //File already exists
		if forceOverwriteFile {
			return os.Remove(file)
		} else {
			return fmt.Errorf("outputfile %s already exists (Use option '-F' to overwrite file)", file)
		}
	}
	// File doesn't exist, check if path is valid
	fileInfo, err := os.Stat(filepath.Dir(file))
	if err != nil || !fileInfo.IsDir() {
		return fmt.Errorf("cannot write file %s. %s does not exist", file, fileInfo.Name())
	}
	return nil
}

// checkAPIHealth accepts a Client with working client-connection and an environmentAlias.
//
// Using the clients connection to the pcap-api it checks whether the api endpoint is healthy in general
// and if it supports requests to the Bosh Environment specified in environmentAlias.
func checkAPIHealth(c *pcap.Client, environmentAlias string) error {

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	statusResponse, err := c.Status(ctx, &pcap.StatusRequest{})
	if err != nil {
		return fmt.Errorf("could not fetch api status: %w", err)
	}

	if !statusResponse.GetHealthy() {
		return fmt.Errorf("pcap-api reported unhealthy status")
	}

	for _, resolverName := range statusResponse.Resolvers {
		if resolverName == fmt.Sprintf("bosh/%v", environmentAlias) {
			return nil
		}
	}
	return fmt.Errorf("pcap-api does not support environment %v", environmentAlias)
}

// setLogLevel sets the log level of the zap.Logger created in setupLogging via atomicLogLevel
//
// It accepts bool values of the verbose and quiet options.
//
// verbose sets the loglevel to Debug, quiet to Warn. The default is Info. If both verbose and quiet are specified, we return an error.
func setLogLevel(verbose bool, quiet bool) error {
	if verbose && quiet {
		return fmt.Errorf("options verbose and quiet are mutually exclusive")
	}

	logLevel := zapcore.InfoLevel
	if verbose {
		logLevel = zapcore.DebugLevel
	} else if quiet {
		logLevel = zapcore.WarnLevel
	}
	atomicLogLevel.SetLevel(logLevel)
	logger.Debug("set log-level", zap.String("log-level", logLevel.String()))
	return nil
}

// configFromFile fetches the content of the specified bosh-config file under path configFilename
// and returns a Config struct.
func configFromFile(configFilename string) (*Config, error) {
	var err error
	configFilename = os.ExpandEnv(configFilename)
	configReader, err := os.Open(configFilename)
	if err != nil {
		return nil, fmt.Errorf("could not open bosh-config %w", err)
	}
	config := &Config{}
	err = yaml.NewDecoder(configReader).Decode(config)
	if err != nil {
		return nil, fmt.Errorf("could not parse the provided bosh-config %w", err)
	}
	logger.Debug("read bosh-config", zap.Any("bosh-config", config))
	return config, nil
}

// urlWithScheme prepends url with https:// if no scheme is specified.
//
// returns url with scheme prefix.
func urlWithScheme(url string) string {
	re := regexp.MustCompile(`^([\w+.-_]+://)`)
	if !re.MatchString(url) {
		return "https://" + url
	}
	logger.Debug("pcap-api URL contains http/https scheme")
	return url
}

// parseAPIURL parses the provided urlString into a URL.
//
// Returns an error if the URL could not be parsed or is not a http(s) URL.
func parseAPIURL(urlString string) (*url.URL, error) {
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return nil, err
	}
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return nil, fmt.Errorf("invalid URL, must start with http or https: %s", parsedURL)
	}
	return parsedURL, nil
}

// getEnvironment searches the provided Config for the environmentAlias.
//
// Returns a matching environment if one exists.
func getEnvironment(environmentAlias string, config *Config) (*Environment, error) {
	for _, environment := range config.Environments {
		if environment.Alias == environmentAlias {
			logger.Debug("found matching bosh-environment", zap.String("environment-alias", environment.Alias))
			return &environment, nil
		}
	}
	return nil, fmt.Errorf("could not find bosh-environment %s in config", environmentAlias)
}

// setupContextCancel starts a goroutine to capture the SIGINT signal that's sent if the user sends CTRL+C.
//
// It then stops the capture using the pcap.CancelCauseFunc cancel.
func setupContextCancel(client *pcap.Client) {
	logger.Debug("registering signal handler for SIGINT")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	go func() {
		logger.Debug("waiting for SIGINT to be sent")
		<-sigChan

		logger.Info("received SIGINT, stopping capture")
		client.StopRequest()
	}()
}

// createEndpointRequest is a helper function to create a pcap.EndpointRequest from parameters.
func createEndpointRequest(token string, deployment string, instanceGroups []string, environmentAlias string) *pcap.EndpointRequest {
	endpointRequest := &pcap.EndpointRequest{
		Request: &pcap.EndpointRequest_Bosh{
			Bosh: &pcap.BoshRequest{
				Token:       token,
				Deployment:  deployment,
				Groups:      instanceGroups,
				Environment: environmentAlias,
			},
		},
	}
	logger.Debug("created endpoint-request", zap.Any("endpoint-request", endpointRequest))
	return endpointRequest
}

// createCaptureOptions is a helper function to create a pcap.CaptureOptions struct from parameters.
func createCaptureOptions(device string, filter string, snaplen uint32) *pcap.CaptureOptions {
	captureOptions := &pcap.CaptureOptions{
		Device:  device,
		Filter:  filter,
		SnapLen: snaplen,
	}
	logger.Debug("created capture-options", zap.Any("capture-options", captureOptions))
	return captureOptions
}

// writeBoshConfig writes the Config to the config-file under configFileName.
func writeBoshConfig(config *Config, configFileName string) error {
	configWriter, err := os.Create(configFileName)
	if err != nil {
		return fmt.Errorf("failed to create bosh-config file %w", err)
	}

	err = yaml.NewEncoder(configWriter).Encode(config)
	if err != nil {
		return fmt.Errorf("failed to update bosh-config file %w", err)
	}
	logger.Info("wrote updated bosh config/tokens to file", zap.String("config-file", configFileName))
	return nil
}

// Config represents the content of the bosh config-file (default location: ~/.bosh/config).
//
// It contains a list of bosh Environments.
type Config struct {
	Environments []Environment `yaml:"environments"`
}

// Environment contains all the necessary information to connect to a specific bosh-director
type Environment struct {
	AccessToken     string       `yaml:"access_token" validate:"required"`
	AccessTokenType string       `yaml:"access_token_type" validate:"required"`
	Alias           string       `yaml:"alias" validate:"required"`
	CaCert          string       `yaml:"ca_cert" validate:"required"`
	RefreshToken    string       `yaml:"refresh_token" validate:"required"`
	URL             string       `yaml:"url" validate:"required,url"`
	DirectorURL     *url.URL     `yaml:"-"`
	UaaURL          *url.URL     `yaml:"-"`
	client          *http.Client `yaml:"-"`
}

// UpdateTokens is the public wrapper func for the bosh Environment struct
//
// It fetches the bosh-uaa URLs from the bosh-director (if necessary)
// and refreshes the bosh authentication tokens.
func (e *Environment) UpdateTokens() error {
	if e.UaaURL == nil {
		err := e.init()
		if err != nil {
			return err
		}
		err = e.fetchUAAURL()
		if err != nil {
			return err
		}
	}
	err := e.refreshTokens()
	if err != nil {
		return fmt.Errorf("failed to refresh bosh access token %w", err)
	}
	return nil
}

// init sets up a Bosh environment by parsing the bosh-director URL (string) from the config-file
// and then sets up the http client for use with either TLS or plain HTTP
func (e *Environment) init() error {
	var err error
	logger := zap.L()

	e.DirectorURL, err = url.Parse(e.URL)
	if err != nil {
		return fmt.Errorf("error parsing environment url (%v) %w", e.URL, err)
	}

	if e.DirectorURL.Scheme == "https" {
		logger.Info("using TLS-encrypted connection to bosh-director", zap.String("bosh-director-url", e.DirectorURL.String()))
		boshCA := x509.NewCertPool()
		ok := boshCA.AppendCertsFromPEM([]byte(e.CaCert))
		if !ok {
			return fmt.Errorf("could not add BOSH Director CA from bosh-config, adding to the cert pool failed %v", e.CaCert) //TODO really output cert here?
		}

		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig.RootCAs = boshCA

		e.client = &http.Client{
			Transport: transport,
		}
	} else {
		logger.Warn("using unencrypted connection to bosh-director", zap.String("bosh-director-url", e.DirectorURL.String()))
		e.client = http.DefaultClient
	}
	return nil
}

// fetchUAAURL connects to the bosh-director API to fetch the bosh-uaa API URL.
func (e *Environment) fetchUAAURL() error {
	res, err := e.client.Do(&http.Request{
		Method: http.MethodGet,
		URL: &url.URL{
			Scheme: e.DirectorURL.Scheme,
			Host:   e.DirectorURL.Host,
			Path:   "/info",
		},
		Header: http.Header{
			"Accept": {"application/json"},
		},
	})
	if err != nil {
		return fmt.Errorf("could not get response from bosh-director %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d from bosh-director", res.StatusCode)
	}

	defer res.Body.Close()

	var info pcap.BoshInfo
	err = json.NewDecoder(res.Body).Decode(&info)
	if err != nil {
		return err
	}

	uaaURL, err := url.Parse(info.UserAuthentication.Options.Url)
	if err != nil {
		return err
	}
	e.UaaURL = uaaURL

	return nil
}

// refreshTokens connects to the bosh-uaa API to fetch updated bosh access- & refresh-token.
func (e *Environment) refreshTokens() error { //TODO: logging
	req := http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: e.UaaURL.Scheme,
			Host:   e.UaaURL.Host,
			Path:   "/oauth/token",
		},
		Header: http.Header{
			"Accept":        {"application/json"},
			"Content-Type":  {"application/x-www-form-urlencoded"},
			"Authorization": {fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte("bosh_cli:")))}, // TODO: the client name is also written in the token
		},
		Body: io.NopCloser(bytes.NewReader([]byte(url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {e.RefreshToken},
		}.Encode()))),
	}
	res, err := e.client.Do(&req)
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

	e.RefreshToken = newTokens.RefreshToken
	e.AccessTokenType = newTokens.TokenType
	e.AccessToken = newTokens.AccessToken

	return nil
}
