package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	log "github.com/sirupsen/logrus"
)

type cfAPIResponse struct {
	Links struct {
		CCv2 struct {
			Href string `json:"href"`
		} `json:"cloud_controller_v2"` //nolint:tagliatelle
		CCv3 struct {
			Href string `json:"href"`
		} `json:"cloud_controller_v3"`
		UAA struct {
			Href string `json:"href"`
		} `json:"uaa"`
	} `json:"links"`
}

type cfAppResponse struct {
	GUID string `json:"guid"`
	Name string `json:"name"`
}

type cfAppStatsResponse struct {
	Resources []struct {
		Type  string `json:"type"`
		Index int    `json:"index"`
		Host  string `json:"host"`
	} `json:"resources"`
}

type CfCaptureHandler struct {
	config     *Config
	ccBaseURL  string
	uaaBaseURL string
}

func NewCfCaptureHandler(config *Config) *CfCaptureHandler {
	return &CfCaptureHandler{
		config: config,
	}
}

func (cf *CfCaptureHandler) handleCapture(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.WriteHeader(http.StatusMethodNotAllowed)

		return
	}

	appId := request.URL.Query().Get("appid")
	appIndicesStr := request.URL.Query()["index"]
	appType := request.URL.Query().Get("type")
	device := request.URL.Query().Get("device")
	filter := request.URL.Query().Get("filter")
	authToken := request.Header.Get("Authorization")

	if appId == "" {
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("appid missing"))

		return
	}

	var appIndices []int

	if len(appIndicesStr) == 0 {
		// FIXME: Should this not be 'all' by default?
		appIndices = append(appIndices, 0) // default value
	} else {
		for _, appIndexStr := range appIndicesStr {
			appIndex, err := strconv.Atoi(appIndexStr)
			if err != nil {
				response.WriteHeader(http.StatusBadRequest)
				response.Write([]byte("could not parse index parameter"))

				return
			}
			appIndices = append(appIndices, appIndex)
		}
	}

	if appType == "" {
		appType = "web" // default value
	}

	if device == "" {
		device = "eth0" // default value
	}

	if authToken == "" {
		response.WriteHeader(http.StatusUnauthorized)
		response.Write([]byte("authentication required"))

		return
	}

	// Check if app can be seen by token
	appVisible, err := cf.isAppVisibleByToken(appId, authToken)
	if err != nil {
		log.Errorf("could not check if app %s can be seen by token %s (%s)", appId, authToken, err)
		response.WriteHeader(http.StatusInternalServerError)

		return
	}
	if appVisible == false {
		log.Infof("app %s cannot be seen by token %s", appId, authToken)
		response.WriteHeader(http.StatusForbidden)

		return
	}

	agentURLs := make([]string, 0, len(appIndices))
	for _, appIndex := range appIndices {
		// App is visible? Great! Let's find out where it lives
		appLocation, err := cf.getAppLocation(appId, appIndex, appType, authToken)
		if err != nil {
			log.Errorf("could not get location of app %s index %d of type %s (%s)", appId, appIndex, appType, err)
		}
		// We found the app's location? Nice! Let's contact the pcap-agent on that VM (index only needed for testing)
		agentURL := fmt.Sprintf("https://%s:%s/capture?appid=%s&index=%d&device=%s&filter=%s", appLocation, cf.config.AgentPort, appId, appIndex, device, filter)
		agentURLs = append(agentURLs, agentURL)
	}

	NewPcapStreamer(cf.config).captureAndStream(agentURLs, &response, request)
}

func (cf *CfCaptureHandler) isAppVisibleByToken(appId string, authToken string) (bool, error) {
	log.Debugf("Checking at %s if app %s can be seen by token %s", cf.ccBaseURL, appId, authToken)
	httpClient := http.DefaultClient
	appURL, err := url.Parse(fmt.Sprintf("%s/apps/%s", cf.ccBaseURL, appId))

	if err != nil {
		return false, err
	}
	req := &http.Request{
		Method: "GET",
		URL:    appURL,
		Header: map[string][]string{
			"Authorization": {authToken},
		},
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	if res.StatusCode != http.StatusOK {
		return false, fmt.Errorf("expected status code %d but got status code %d", http.StatusOK, res.StatusCode)
	}

	var appResponse *cfAppResponse
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return false, err
	}
	err = json.Unmarshal(data, &appResponse)
	if err != nil {
		return false, err
	}

	if appResponse.GUID != appId {
		return false, fmt.Errorf("expected app id %s but got app id %s (%s)", appId, appResponse.GUID, appResponse.Name)
	}

	return true, nil
}

func (cf *CfCaptureHandler) setup() {
	log.Info("Discovering CF API endpoints...")
	response, err := http.Get(cf.config.CfAPI)

	if err != nil {
		log.Fatalf("Could not fetch CF API from %s (%s)", cf.config.CfAPI, err)
	}

	var apiResponse *cfAPIResponse
	data, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Could not read CF API response: %s", err)
	}
	err = json.Unmarshal(data, &apiResponse)
	if err != nil {
		log.Fatalf("Could not parse CF API response: %s", err)
	}

	cf.ccBaseURL = apiResponse.Links.CCv3.Href
	cf.uaaBaseURL = apiResponse.Links.UAA.Href
	log.Info("Done.")
}

func (cf *CfCaptureHandler) getAppLocation(appId string, appIndex int, appType string, authToken string) (string, error) {
	// FIXME refactor with getInstances into common cf client that uses authToken
	log.Debugf("Trying to get location of app %s with index %d of type %s", appId, appIndex, appType)
	httpClient := http.DefaultClient
	appURL, err := url.Parse(fmt.Sprintf("%s/apps/%s/processes/%s/stats", cf.ccBaseURL, appId, appType))

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

	res, err := httpClient.Do(req)

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
