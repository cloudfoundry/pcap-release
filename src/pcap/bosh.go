package pcap

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"go.uber.org/zap"

	"github.com/cloudfoundry/pcap-release/src/pcap/bosh"
)

type BoshResolverConfig struct {
	RawDirectorURL   string    `yaml:"director_url" validate:"required,url"`
	EnvironmentAlias string    `yaml:"alias" validate:"required"`
	AgentPort        int       `yaml:"agent_port" validate:"required,gt=0,lte=65535"` //TODO: what about api.agents.port?
	TokenScope       string    `yaml:"token_scope" validate:"required"`
	MTLS             MutualTLS `yaml:"mtls" validate:"omitempty,structonly"` // TODO: this skips validation of the nested fields
}

type BoshResolver struct {
	client      *http.Client
	uaaURLs     []string
	config      BoshResolverConfig
	directorURL *url.URL
	logger      *zap.Logger
}

func NewBoshResolver(config BoshResolverConfig) (*BoshResolver, error) {
	directorURL, err := url.Parse(config.RawDirectorURL)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize BoshResolver for environment %s. %w", config.EnvironmentAlias, err)
	}

	resolver := &BoshResolver{
		logger:      zap.L().With(zap.String(LogKeyHandler, config.EnvironmentAlias)),
		config:      config,
		directorURL: directorURL,
	}

	err = resolver.setup()
	if err != nil {
		return nil, err
	}
	return resolver, err
}

func (br *BoshResolver) Name() string {
	return fmt.Sprintf("bosh/%s", br.config.EnvironmentAlias)
}

func (br *BoshResolver) CanResolve(request *EndpointRequest) bool {
	if boshRequest := request.GetBosh(); boshRequest != nil {
		return boshRequest.Environment == br.config.EnvironmentAlias
	}
	return false
}

func (br *BoshResolver) Resolve(request *EndpointRequest, logger *zap.Logger) ([]AgentEndpoint, error) { // TODO why do we pass the logger here?
	logger.Info("resolving endpoints for bosh request")

	err := br.validate(request)
	if err != nil {
		return nil, err
	}

	boshRequest := request.GetBosh()

	err = br.authenticate(boshRequest.Token)
	if err != nil {
		return nil, err
	}

	instances, _, err := br.getInstances(boshRequest.Deployment, boshRequest.Token)
	if err != nil {
		logger.Error("failed to get instances from bosh-director", zap.String(LogKeyTarget, ""))
		return nil, err
	}

	var endpoints []AgentEndpoint
	for _, instance := range instances {
		identifier := strings.Join([]string{instance.Job, instance.Id}, "/")
		endpoints = append(endpoints, AgentEndpoint{IP: instance.Ips[0], Port: br.config.AgentPort, Identifier: identifier})
	}

	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no matching endpoints found")
	}

	logger.Debug("received AgentEndpoints from Bosh Director", zap.Any("agent-endpoint", endpoints))
	return endpoints, nil
}

func (br *BoshResolver) validate(endpointRequest *EndpointRequest) error {
	boshRequest := endpointRequest.GetBosh()

	if boshRequest == nil {
		return fmt.Errorf("invalid message: br: %w", errNilField)
	}

	if boshRequest.Token == "" {
		return fmt.Errorf("invalid message: token: %w", errEmptyField)
	}

	if boshRequest.Deployment == "" {
		return fmt.Errorf("invalid message: deployment: %w", errEmptyField)
	}

	if boshRequest.Environment == "" {
		return fmt.Errorf("invalid message: environment: %w", errEmptyField)
	}

	if len(boshRequest.Groups) == 0 {
		return fmt.Errorf("invalid message: instance group(s): %w", errEmptyField)
	}

	return nil
}

func (br *BoshResolver) setup() error {
	br.logger.Info("setting Up BoshResolver", zap.Any("resolver-config", br.config))

	if br.config.MTLS.CertificateAuthority == "" {
		br.client = http.DefaultClient
	} else {
		data, err := os.ReadFile(br.config.MTLS.CertificateAuthority)
		if err != nil {
			return fmt.Errorf("could not load bosh-director ca from %s (%s)", br.config.MTLS.CertificateAuthority, err)
		}

		boshCA := x509.NewCertPool()
		ok := boshCA.AppendCertsFromPEM(data)

		if !ok {
			return fmt.Errorf("could not add bosh-director ca from %s, adding to the cert pool failed", br.config.MTLS.CertificateAuthority)
		}

		br.client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: boshCA,
				},
			},
		}
	}

	br.logger.Info("discovering bosh-UAA endpoint")
	infoEndpoint := br.directorURL.JoinPath("/info").String()
	response, err := br.client.Get(infoEndpoint)

	if err != nil {
		return fmt.Errorf("could not fetch bosh-director API from %v: %w", br.config.RawDirectorURL, err)
	}

	var apiResponse *bosh.Info
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("could not read bosh-director API response: %s", err)
	}
	err = json.Unmarshal(data, &apiResponse)
	if err != nil {
		return fmt.Errorf("could not parse bosh-director API response: %s", err)
	}

	br.uaaURLs = apiResponse.UserAuthentication.Options.Urls

	br.logger.Info("connected to bosh-director", zap.Any("bosh-director", apiResponse))

	return nil
}

func (br *BoshResolver) authenticate(authToken string) error {

	allowed, err := VerifyJwt(authToken, br.config.TokenScope, br.uaaURLs)
	if err != nil {
		return fmt.Errorf("could not verify token %s (%s)", authToken, err)
	}

	if !allowed {
		return fmt.Errorf("token %s does not have the permissions or is not supported", authToken)
	}

	return nil
}

func (br *BoshResolver) getInstances(deployment string, authToken string) ([]bosh.Instance, int, error) {
	br.logger.Debug("checking token-permissions", zap.String("director-url", br.directorURL.String()), zap.String("deployment", deployment)) //, zap.String("token", authToken)) //TODO authToken is userspecific
	instancesURL, err := url.Parse(fmt.Sprintf("%s/deployments/%s/instances", br.directorURL, deployment))
	if err != nil {
		return nil, 0, err
	}

	req := &http.Request{
		Method: http.MethodGet,
		URL:    instancesURL,
		Header: map[string][]string{
			"Authorization": {"Bearer " + authToken},
		},
	}

	res, err := br.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request to Bosh-director failed: %v", zap.Error(err))
	}

	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, res.StatusCode, fmt.Errorf("expected status code %d but got status code %d: %s", http.StatusOK, res.StatusCode, string(data))
	}

	var response []bosh.Instance

	err = json.Unmarshal(data, &response)
	if err != nil {
		return nil, 0, err
	}

	return response, res.StatusCode, nil
}
