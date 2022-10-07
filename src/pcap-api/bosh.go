package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/url"
	"time"
)

type BoshCaptureHandler struct {
	config  *Config
	client  *http.Client
	uaaUrls []string
}

func NewBoshCaptureHandler(config *Config) *BoshCaptureHandler {
	return &BoshCaptureHandler{
		config: config,
	}
}

type boshInfo struct {
	Name            string `json:"name"`
	Uuid            string `json:"uuid"`
	Version         string `json:"version"`
	Cpi             string `json:"cpi"`
	StemcellOs      string `json:"stemcell_os"`
	StemcellVersion string `json:"stemcell_version"`

	UserAuthentication struct {
		Type    string `json:"type"`
		Options struct {
			Url  string   `json:"url"`
			Urls []string `json:"urls"`
		} `json:"options"`
	} `json:"user_authentication"`
}

type boshInstance struct {
	AgentId     string    `json:"agent_id"`
	Cid         string    `json:"cid"`
	Job         string    `json:"job"`
	Index       int       `json:"index"`
	Id          string    `json:"id"`
	Az          string    `json:"az"`
	Ips         []string  `json:"ips"`
	VmCreatedAt time.Time `json:"vm_created_at"`
	ExpectsVm   bool      `json:"expects_vm"`
}

func (b *boshInstance) String() string {
	return fmt.Sprintf("%s/%s %s", b.Job, b.Id, b.Ips)
}

func (bosh *BoshCaptureHandler) handleCapture(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.WriteHeader(http.StatusMethodNotAllowed)

		return
	}

	deployment := request.URL.Query().Get("deployment")
	groups := toSet(request.URL.Query()["group"])

	instanceIds := toSet(request.URL.Query()["instance"])

	device := request.URL.Query().Get("device")
	filter := request.URL.Query().Get("filter")
	authToken := request.Header.Get("Authorization")

	log.Debugf("bosh capture request for deployment: %s, group(s): %v, instance(s): %v, filter: %q, device: %q", deployment, groups, instanceIds, filter, device)

	if deployment == "" {
		response.WriteHeader(http.StatusBadRequest)
		_, _ = response.Write([]byte("deployment missing"))

		return
	}
	// TODO: add check for len groups > 0

	if len(groups) < 1 {
		response.WriteHeader(http.StatusBadRequest)
		_, _ = response.Write([]byte("instance group(s) missing"))

		return
	}

	if device == "" {
		device = "eth0" // default value
	}

	if authToken == "" {
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = response.Write([]byte("authentication required"))

		return
	}

	err := verifyJwt(authToken, "bosh.admin", bosh.uaaUrls)
	if err != nil {
		log.Errorf("could not verify token %s (%s)", authToken, err)
		response.WriteHeader(http.StatusForbidden)
		_, _ = response.Write([]byte(fmt.Sprintf("could not verify token: %v", err)))

		return
	}

	// Check if app can be seen by token
	instances, err := bosh.getInstances(deployment, authToken)
	if err != nil {
		// FIXME: This could be an auth error as well.
		log.Errorf("could not check if app %s can be seen by token %s (%s)", deployment, authToken, err)
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	var selectedInstances []boshInstance

	for _, instance := range instances {
		if _, hasGroup := groups[instance.Job]; !hasGroup {
			continue
		}

		// select all instance IDs when no explicit one is given.
		if len(instanceIds) > 0 {
			if _, hasId := instanceIds[instance.Id]; !hasId {
				continue
			}
		}

		selectedInstances = append(selectedInstances, instance)
	}

	log.Debugf("selected instances: %v", selectedInstances)

	agentURLs := make([]string, 0, len(selectedInstances))

	for _, instance := range selectedInstances {
		ip := instance.Ips[0]

		agentURL := fmt.Sprintf("https://%s:%s/capture/bosh?device=%s&filter=%s", ip, bosh.config.AgentPort, device, filter)
		agentURLs = append(agentURLs, agentURL)
	}

	NewPcapStreamer(bosh.config).captureAndStream(agentURLs, &response, request)
}

type StringSet map[string]struct{}

func toSet(strings []string) StringSet {
	set := make(StringSet, len(strings))
	for _, s := range strings {
		set[s] = struct{}{}
	}
	return set
}

func (bosh *BoshCaptureHandler) getInstances(deployment string, authToken string) ([]boshInstance, error) {
	log.Debugf("Checking at %s if deployment %s can be seen by token %s", bosh.config.BoshDirectorAPI, deployment, authToken)
	url, err := url.Parse(fmt.Sprintf("%s/deployments/%s/instances", bosh.config.BoshDirectorAPI, deployment))

	if err != nil {
		return nil, err
	}
	req := &http.Request{
		Method: "GET",
		URL:    url,
		Header: map[string][]string{
			"Authorization": {authToken},
		},
	}

	res, err := bosh.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected status code %d but got status code %d", http.StatusOK, res.StatusCode)
	}

	var response []boshInstance
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (bosh *BoshCaptureHandler) setup() {
	log.Info("Discovering BOSH Director endpoint...")

	bosh.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// FIXME: add BOSH director CA
				InsecureSkipVerify: true,
			},
		},
	}

	response, err := bosh.client.Get(bosh.config.BoshDirectorAPI + "/info")

	if err != nil {
		log.Fatalf("Could not fetch BOSH Director API from %s (%s)", bosh.config.BoshDirectorAPI, err)
	}

	var apiResponse *boshInfo
	data, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Could not read BOSH Director API response: %s", err)
	}
	err = json.Unmarshal(data, &apiResponse)
	if err != nil {
		log.Fatalf("Could not parse BOSH Director API response: %s", err)
	}

	bosh.uaaUrls = apiResponse.UserAuthentication.Options.Urls

	log.Infof("Connected to BOSH Director '%s' (%s), version %s on %s. UAA URLs: %v", apiResponse.Name, apiResponse.Uuid, apiResponse.Version, apiResponse.Cpi, bosh.uaaUrls)
}
