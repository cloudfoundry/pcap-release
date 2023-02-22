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
)

type BoshHandler struct {
	Environment bosh.Environment
	client      *http.Client
	uaaURLS     []string
}

func NewBoshHandler(environment bosh.Environment) *BoshHandler {
	boshHandler := &BoshHandler{Environment: environment}
	boshHandler.setup()
	return boshHandler
}

func (boshHandler *BoshHandler) name() string {
	return "bosh"
}

func (boshHandler *BoshHandler) canHandle(request *EndpointRequest) bool {
	return request.GetBosh() != nil
}

func (boshHandler *BoshHandler) handle(request *EndpointRequest, log *zap.Logger) ([]AgentEndpoint, error) {
	log = log.With(zap.String("handler", boshHandler.name()))
	log.Info("Handling request")

	boshRequest, err := boshHandler.validate(request)
	if err != nil {
		return nil, err
	}

	boshHandler.authenticate(boshRequest.Token)

	instances, _, err := boshHandler.getInstances(boshRequest.Deployment, boshRequest.Token)
	if err != nil {
		// TODO e.g. invalid token
		panic(err)
	}
	//log.Info("%v", i)
	var endpoints []AgentEndpoint
	for _, instance := range instances {
		identifier := fmt.Sprintf(instance.Job, "/", instance.Id)
		endpoints = append(endpoints, AgentEndpoint{IP: instance.Ips[0], Port: 8080, Identifier: identifier}) //TODO:?
	}

	if len(endpoints) == 0 {
		fmt.Errorf("no matching endpoints found")
	}

	return endpoints, nil
}

func (boshHandler *BoshHandler) validate(endpointRequest *EndpointRequest) (*BoshQuery, error) {
	boshRequest := endpointRequest.GetBosh()

	if boshRequest == nil {
		return nil, fmt.Errorf("invalid message: boshHandler: %w", errNilField)
	}

	if boshRequest.Token == "" {
		return nil, fmt.Errorf("invalid message: token: %w", errEmptyField)
	}

	if boshRequest.Deployment == "" {
		return nil, fmt.Errorf("invalid message: deployment: %w", errEmptyField)
	}

	if len(boshRequest.Groups) == 0 {
		return nil, fmt.Errorf("invalid message: instance group(s): %w", errEmptyField)
	}

	return boshRequest, nil
}

func (boshHandler *BoshHandler) setup() {
	log.Info("Setting Up BoshHandler for %s", boshHandler.Environment.Alias)

	if boshHandler.Environment.CaCert == "" {
		boshHandler.client = http.DefaultClient // fixme required?
	} else {
		data, err := os.ReadFile(boshHandler.Environment.CaCert)

		if err != nil {
			log.Fatalf("Could not load BOSH Director CA from %s (%s)", boshHandler.Environment.CaCert, err)
		}

		boshCA := x509.NewCertPool()
		ok := boshCA.AppendCertsFromPEM(data)

		if !ok {
			log.Fatalf("Could not add BOSH Director CA from %s, adding to the cert pool failed.", boshHandler.Environment.CaCert)
		}

		boshHandler.client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: boshCA,
				},
			},
		}

	}

	log.Info("Discovering BOSH Director endpoint...")
	response, err := boshHandler.client.Get(boshHandler.Environment.Url + "/info")

	if err != nil {
		log.Fatalf("Could not fetch BOSH Director API from %s (%s)", boshHandler.Environment.Url, err)
	}

	var apiResponse *bosh.Info
	data, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Could not read BOSH Director API response: %s", err)
	}
	err = json.Unmarshal(data, &apiResponse)
	if err != nil {
		log.Fatalf("Could not parse BOSH Director API response: %s", err)
	}

	boshHandler.uaaURLS = apiResponse.UserAuthentication.Options.Urls

	log.Infof("Connected to BOSH Director '%s' (%s), version %s on %s. UAA URLs: %v", apiResponse.Name, apiResponse.Uuid, apiResponse.Version, apiResponse.Cpi, boshHandler.uaaURLS)

}

func (boshHandler *BoshHandler) authenticate(authToken string) {

	allowed, err := VerifyJwt(authToken, "bosh.admin", boshHandler.uaaURLS)
	if err != nil {
		log.Errorf("could not verify token %s (%s)", authToken, err) //TODO
	}

	if !allowed {
		log.Errorf("token %s does not have the permissions or is not supported", authToken) //TODO
	}
}

func (boshHandler *BoshHandler) getInstances(deployment string, authToken string) ([]bosh.Instance, int, error) {
	log.Debugf("Checking at %s if deployment %s can be seen by token %s", boshHandler.Environment.Url, deployment, authToken)
	instancesUrl, err := url.Parse(fmt.Sprintf("%s/deployments/%s/instances", boshHandler.Environment.Url, deployment))

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

	res, err := boshHandler.client.Do(req)
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
