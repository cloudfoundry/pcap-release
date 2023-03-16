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

	log "github.com/sirupsen/logrus"
	"go.uber.org/zap"

	"github.com/cloudfoundry/pcap-release/src/pcap/bosh"
)

type BoshResolver struct {
	environment bosh.Environment
	client      *http.Client
	uaaURLs     []string
	agentPort   int
}

func NewBoshResolver(environment bosh.Environment, agentPort int) (*BoshResolver, error) {
	resolver := &BoshResolver{environment: environment, agentPort: agentPort} // TODO: get agent port from where?
	err := resolver.setup()
	if err != nil {
		return nil, err
	}
	return resolver, err
}

func (br *BoshResolver) Name() string {
	// TODO we need to differentiate between bosh resolvers for different environments (i.e. bootstrap-bosh, bosh. This would take some refactoring, e.g. in pcap.proto StatusResponse
	// return fmt.Sprintf("bosh/%s", br.environment.Alias)
	return "bosh"
}

func (br *BoshResolver) CanResolve(request *EndpointRequest) bool {
	return request.GetBosh() != nil
}

func (br *BoshResolver) Resolve(request *EndpointRequest, log *zap.Logger) ([]AgentEndpoint, error) {
	log = log.With(zap.String(LogKeyHandler, br.Name()))
	log.Info("Resolving endpoints for bosh request")

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
		log.Error("failed to get instances from bosh-director", zap.String(LogKeyTarget, ""))
		return nil, err
	}

	var endpoints []AgentEndpoint
	for _, instance := range instances {
		identifier := strings.Join([]string{instance.Job, instance.Id}, "/")
		endpoints = append(endpoints, AgentEndpoint{IP: instance.Ips[0], Port: br.agentPort, Identifier: identifier}) //TODO: defaultport ok here?
	}

	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no matching endpoints found")
	}

	log.Debug("received AgentEndpoints from Bosh Director", zap.Any("agent-endpoint", endpoints))
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

	if len(boshRequest.Groups) == 0 {
		return fmt.Errorf("invalid message: instance group(s): %w", errEmptyField)
	}

	return nil
}

func (br *BoshResolver) setup() error {
	log.Infof("Setting Up BoshResolver for %s", br.environment.Alias)

	if br.environment.CaCert == "" {
		br.client = http.DefaultClient
	} else {
		data, err := os.ReadFile(br.environment.CaCert)
		if err != nil {
			return fmt.Errorf("could not load BOSH Director CA from %s (%s)", br.environment.CaCert, err)
		}

		boshCA := x509.NewCertPool()
		ok := boshCA.AppendCertsFromPEM(data)

		if !ok {
			return fmt.Errorf("could not add BOSH Director CA from %s, adding to the cert pool failed.", br.environment.CaCert)
		}

		br.client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: boshCA,
				},
			},
		}
	}

	log.Info("Discovering BOSH Director endpoint...")
	response, err := br.client.Get(br.environment.RawDirectorURL + "/info")

	if err != nil {
		return fmt.Errorf("could not fetch BOSH Director API from %s (%s)", br.environment.RawDirectorURL, err)
	}

	var apiResponse *bosh.Info
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("could not read BOSH Director API response: %s", err)
	}
	err = json.Unmarshal(data, &apiResponse)
	if err != nil {
		return fmt.Errorf("could not parse BOSH Director API response: %s", err)
	}

	br.uaaURLs = apiResponse.UserAuthentication.Options.Urls

	log.Infof("Connected to BOSH Director '%s' (%s), version %s on %s. UAA URLs: %v", apiResponse.Name, apiResponse.Uuid, apiResponse.Version, apiResponse.Cpi, br.uaaURLs)

	return nil
}

func (br *BoshResolver) authenticate(authToken string) error {

	allowed, err := VerifyJwt(authToken, "bosh.admin", br.uaaURLs)
	if err != nil {
		return fmt.Errorf("could not verify token %s (%s)", authToken, err)
	}

	if !allowed {
		return fmt.Errorf("token %s does not have the permissions or is not supported", authToken)
	}

	return nil
}

func (br *BoshResolver) getInstances(deployment string, authToken string) ([]bosh.Instance, int, error) {
	log.Debugf("Checking at %s if deployment %s can be seen by token %s", br.environment.RawDirectorURL, deployment, authToken)
	instancesURL, err := url.Parse(fmt.Sprintf("%s/deployments/%s/instances", br.environment.RawDirectorURL, deployment))
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
