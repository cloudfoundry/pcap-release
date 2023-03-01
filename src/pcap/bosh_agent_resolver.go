package pcap

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/cloudfoundry/pcap-release/src/pcap/bosh"
	log "github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type BoshAgentResolver struct {
	environment bosh.Environment
	client      *http.Client
	uaaURLS     []string
	agentMTLS   AgentMTLS
}

func NewBoshAgentResolver(environment bosh.Environment, agentMTLS AgentMTLS) *BoshAgentResolver {
	resolver := &BoshAgentResolver{environment: environment, agentMTLS: agentMTLS}
	//TODO: include Setup() here?
	return resolver
}

func (boshAgentResolver *BoshAgentResolver) name() string {
	return "bosh"
}

func (boshAgentResolver *BoshAgentResolver) canResolve(request *EndpointRequest) bool {
	return request.GetBosh() != nil
}

func (boshAgentResolver *BoshAgentResolver) resolve(request *EndpointRequest, log *zap.Logger) ([]AgentEndpoint, error) {
	log = log.With(zap.String("resolver", boshAgentResolver.name()))
	//log.Info("Resolving endpoints for bosh request")
	// TODO: proper logging

	err := boshAgentResolver.validate(request)
	if err != nil {
		return nil, err
	}

	boshRequest := request.GetBosh()

	err = boshAgentResolver.authenticate(boshRequest.Token)
	if err != nil {
		return nil, err
	}

	instances, _, err := boshAgentResolver.getInstances(boshRequest.Deployment, boshRequest.Token)
	if err != nil {
		// TODO e.g. invalid token
		return nil, err
	}
	//log.Info("%v", i)
	var endpoints []AgentEndpoint
	for _, instance := range instances {
		identifier := strings.Join([]string{instance.Job, instance.Id}, "/")
		endpoints = append(endpoints, AgentEndpoint{IP: instance.Ips[0], Port: boshAgentResolver.agentMTLS.DefaultPort, Identifier: identifier}) //TODO: defaultport ok here?
	}

	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no matching endpoints found")
	}

	return endpoints, nil
}

func (boshAgentResolver *BoshAgentResolver) validate(endpointRequest *EndpointRequest) error {
	boshRequest := endpointRequest.GetBosh()

	if boshRequest == nil {
		return fmt.Errorf("invalid message: boshAgentResolver: %w", errNilField)
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

func (boshAgentResolver *BoshAgentResolver) Setup() error { //TODO: make private?
	log.Infof("Setting Up BoshAgentResolver for %s", boshAgentResolver.environment.Alias)

	if boshAgentResolver.environment.CaCert == "" {
		boshAgentResolver.client = http.DefaultClient // fixme required?
	} else {
		data, err := os.ReadFile(boshAgentResolver.environment.CaCert)
		if err != nil {
			return fmt.Errorf("Could not load BOSH Director CA from %s (%s)", boshAgentResolver.environment.CaCert, err)
		}

		boshCA := x509.NewCertPool()
		ok := boshCA.AppendCertsFromPEM(data)

		if !ok {
			return fmt.Errorf("Could not add BOSH Director CA from %s, adding to the cert pool failed.", boshAgentResolver.environment.CaCert)
		}

		boshAgentResolver.client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: boshCA,
				},
			},
		}
	}

	log.Info("Discovering BOSH Director endpoint...")
	response, err := boshAgentResolver.client.Get(boshAgentResolver.environment.Url + "/info")

	if err != nil {
		return fmt.Errorf("Could not fetch BOSH Director API from %s (%s)", boshAgentResolver.environment.Url, err)
	}

	var apiResponse *bosh.Info
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("Could not read BOSH Director API response: %s", err)
	}
	err = json.Unmarshal(data, &apiResponse)
	if err != nil {
		return fmt.Errorf("Could not parse BOSH Director API response: %s", err)
	}

	boshAgentResolver.uaaURLS = apiResponse.UserAuthentication.Options.Urls

	log.Infof("Connected to BOSH Director '%s' (%s), version %s on %s. UAA URLs: %v", apiResponse.Name, apiResponse.Uuid, apiResponse.Version, apiResponse.Cpi, boshAgentResolver.uaaURLS)

	return nil
}

func (boshAgentResolver *BoshAgentResolver) authenticate(authToken string) error {

	allowed, err := VerifyJwt(authToken, "bosh.admin", boshAgentResolver.uaaURLS)
	if err != nil {
		return fmt.Errorf("could not verify token %s (%s)", authToken, err)
	}

	if !allowed {
		return fmt.Errorf("token %s does not have the permissions or is not supported", authToken)
	}

	return nil
}

func (boshAgentResolver *BoshAgentResolver) getInstances(deployment string, authToken string) ([]bosh.Instance, int, error) {
	log.Debugf("Checking at %s if deployment %s can be seen by token %s", boshAgentResolver.environment.Url, deployment, authToken)
	instancesUrl, err := url.Parse(fmt.Sprintf("%s/deployments/%s/instances", boshAgentResolver.environment.Url, deployment))

	if err != nil {
		return nil, 0, err
	}
	req := &http.Request{
		Method: "GET",
		URL:    instancesUrl,
		Header: map[string][]string{
			"Authorization": {"Bearer " + authToken},
		},
	}

	res, err := boshAgentResolver.client.Do(req)
	if err != nil {
		return nil, 0, err
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
