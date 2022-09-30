package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/url"
	"time"
)

type BoshCaptureHandler struct {
	config *Config
	client *http.Client
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

	instanceIds := request.URL.Query()["instance"]
	instanceIdSet := toSet(instanceIds)

	device := request.URL.Query().Get("device")
	filter := request.URL.Query().Get("filter")
	authToken := request.Header.Get("Authorization")

	log.Debugf("bosh capture request for deployment: %s, group(s): %v, instance(s): %v, filter: %q, device: %q", deployment, groups, instanceIds, filter, device)

	if deployment == "" {
		response.WriteHeader(http.StatusBadRequest)
		_, _ = response.Write([]byte("deployment missing"))

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

	err := verifyJwt(authToken, "bosh.admin")
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
			if _, hasId := instanceIdSet[instance.Id]; !hasId {
				continue
			}
		}

		selectedInstances = append(selectedInstances, instance)
	}

	log.Debugf("selected instances: %v", selectedInstances)

	//packets := make(chan packetMessage, 1000)

	//for _, index := range instances {
	//	go func(appIndex int, packets chan packetMessage) {
	//		defer func() {
	//			packets <- packetMessage{
	//				packet: nil,
	//				done:   true,
	//              // TODO: should this not be a waitgroup instead?
	//			}
	//		}()
	//		// App is visible? Great! Let's find out where it lives
	//		appLocation, err := bosh.getAppLocation(appId, appIndex, appType, authToken)
	//		if err != nil {
	//			log.Errorf("could not get location of app %s index %d of type %s (%s)", appId, appIndex, appType, err)
	//			return
	//		}
	//		// We found the app's location? Nice! Let's contact the pcap-agent on that VM (index only needed for testing)
	//		agentURL := fmt.Sprintf("https://%s:%s/capture?appid=%s&index=%d&device=%s&filter=%s", appLocation, bosh.config.AgentPort, appId, appIndex, device, filter)
	//		pcapStream, err := bosh.getPcapStream(agentURL)
	//		if err != nil {
	//			log.Errorf("could not get pcap stream from URL %s (%s)", agentURL, err)
	//			// FIXME(max): we see 'http: superfluous response.WriteHeader call' if errors occur in this loop because there is only one response but each routine can fail on it's own.
	//			//             there is more than one occurrence.
	//			response.WriteHeader(http.StatusBadGateway)
	//			return
	//		}
	//		defer pcapStream.Close()
	//
	//		// Stream the pcap back to the client
	//		pcapReader, err := pcapgo.NewReader(pcapStream)
	//		if err != nil {
	//			log.Errorf("could not create pcap reader from pcap stream %s (%s)", pcapStream, err)
	//			response.WriteHeader(http.StatusBadGateway)
	//			return
	//		}
	//		for {
	//			data, capInfo, err := pcapReader.ReadPacketData()
	//			if err != nil {
	//				handleIOError(err)
	//				return
	//			}
	//			log.Debugf("Read packet: Time %s Length %d Captured %d", capInfo.Timestamp, capInfo.Length, capInfo.CaptureLength)
	//			packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	//			packet.Metadata().CaptureInfo = capInfo
	//			packets <- packetMessage{
	//				packet: packet,
	//				done:   false,
	//			}
	//		}
	//	}(index, packets)
	//}

	// Collect all packets from multiple input streams and merge them into one output stream
	w := pcapgo.NewWriter(response)
	err = w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	if err != nil {
		log.Error(err)
		return
	}

	//bytesTotal := 24 // pcap header is 24 bytes
	//done := 0
	//for msg := range packets {
	//	if msg.packet != nil {
	//		err = w.WritePacket(msg.packet.Metadata().CaptureInfo, msg.packet.Data())
	//		if err != nil {
	//			handleIOError(err)
	//			return
	//		}
	//		bytesTotal += msg.packet.Metadata().Length
	//		if f, ok := response.(http.Flusher); ok {
	//			f.Flush()
	//		}
	//	}
	//	if msg.done {
	//		done++
	//		if done == len(appIndices) {
	//			log.Infof("Done capturing. Wrote %d bytes from %s to %s", bytesTotal, request.URL, request.RemoteAddr)
	//			return
	//		}
	//	}
	//}
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
	appURL, err := url.Parse(fmt.Sprintf("%s/deployments/%s/instances", bosh.config.BoshDirectorAPI, deployment))

	if err != nil {
		return nil, err
	}
	req := &http.Request{
		Method: "GET",
		URL:    appURL,
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

	var appResponse []boshInstance
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &appResponse)
	if err != nil {
		return nil, err
	}

	return appResponse, nil
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

	log.Infof("Connected to BOSH Director '%s' (%s), version %s on %s", apiResponse.Name, apiResponse.Uuid, apiResponse.Version, apiResponse.Cpi)
}

func (bosh *BoshCaptureHandler) getAppLocation(appId string, appIndex int, appType string, authToken string) (string, error) {
	// FIXME refactor with getInstances into common bosh client that uses authToken
	log.Debugf("Trying to get location of app %s with index %d of type %s", appId, appIndex, appType)
	appURL, err := url.Parse(fmt.Sprintf("%s/apps/%s/processes/%s/stats", bosh.config.BoshDirectorAPI, appId, appType))

	if err != nil {
		return "", err
	}
	req := &http.Request{
		Method: "GET",
		URL:    appURL,
		Header: map[string][]string{
			"Authorization": {authToken},
		},
	}

	res, err := bosh.client.Do(req)

	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("expected status code %d but got status code %d", http.StatusOK, res.StatusCode)
	}

	var appStatsResponse *cfAppStatsResponse
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(data, &appStatsResponse)
	if err != nil {
		return "", err
	}

	if len(appStatsResponse.Resources) < appIndex+1 {
		return "", fmt.Errorf("expected at least %d elements in stats array for app %s with index %d of type %s but got %d",
			appIndex+1, appId, appIndex, appType, len(appStatsResponse.Resources))
	}

	for _, process := range appStatsResponse.Resources {
		if process.Index == appIndex {
			if process.Type == appType {
				return process.Host, nil
			}
		}
	}

	return "", fmt.Errorf("could not find process with index %d of type %s for app %s", appIndex, appType, appId)
}
