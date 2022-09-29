package main

import (
	"encoding/json"
	"fmt"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type BoshCaptureHandler struct {
	config      *Config
	directorURL string
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

func (bosh *BoshCaptureHandler) handleCapture(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.WriteHeader(http.StatusMethodNotAllowed)

		return
	}

	deployment := request.URL.Query().Get("deployment")
	// instances := request.URL.Query()["instance"]
	device := request.URL.Query().Get("device")
	// filter := request.URL.Query().Get("filter")
	authToken := request.Header.Get("Authorization")

	if deployment == "" {
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("deployment missing"))

		return
	}

	if device == "" {
		device = "eth0" // default value
	}

	if authToken == "" {
		response.WriteHeader(http.StatusUnauthorized)
		response.Write([]byte("authentication required"))

		return
	}

	err := verifyToken(authToken)

	// Check if app can be seen by token
	appVisible, err := bosh.getInstances(deployment, authToken)
	if err != nil {
		log.Errorf("could not check if app %s can be seen by token %s (%s)", deployment, authToken, err)
		response.WriteHeader(http.StatusInternalServerError)

		return
	}
	if appVisible == false {
		log.Infof("deployment %s cannot be seen by token %s", deployment, authToken)
		response.WriteHeader(http.StatusForbidden)

		return
	}

	//handleIOError := func(err error) {
	//	if errors.Is(err, io.EOF) {
	//		log.Debug("Done capturing.")
	//	} else {
	//		log.Errorf("Error during capture: %s", err)
	//	}
	//}

	type packetMessage struct {
		packet gopacket.Packet
		done   bool
	}
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

func verifyToken(tokenString string) error {

	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return token.Header["kid"], nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println(claims["foo"], claims["nbf"])
	} else {
		fmt.Println(err)
	}
	return nil
}

func (bosh *BoshCaptureHandler) getInstances(deployment string, authToken string) (bool, error) {
	log.Debugf("Checking at %s if deployment %s can be seen by token %s", bosh.directorURL, deployment, authToken)
	httpClient := http.DefaultClient
	appURL, err := url.Parse(fmt.Sprintf("%s/deployments/%s/instances", bosh.directorURL, deployment))

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

	if appResponse.GUID != deployment {
		return false, fmt.Errorf("expected app id %s but got app id %s (%s)", deployment, appResponse.GUID, appResponse.Name)
	}

	return true, nil
}

func (bosh *BoshCaptureHandler) setup() {
	log.Info("Discovering CF API endpoints...")
	response, err := http.Get(bosh.config.CfAPI)

	if err != nil {
		log.Fatalf("Could not fetch CF API from %s (%s)", bosh.config.CfAPI, err)
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

	bosh.directorURL = apiResponse.Links.CCv3.Href
	log.Info("Done.")
}

func (bosh *BoshCaptureHandler) getAppLocation(appId string, appIndex int, appType string, authToken string) (string, error) {
	// FIXME refactor with getInstances into common bosh client that uses authToken
	log.Debugf("Trying to get location of app %s with index %d of type %s", appId, appIndex, appType)
	httpClient := http.DefaultClient
	appURL, err := url.Parse(fmt.Sprintf("%s/apps/%s/processes/%s/stats", bosh.directorURL, appId, appType))

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
	data, err := ioutil.ReadAll(res.Body)
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
