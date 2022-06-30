package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/containerd/go-runc"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"
	"io"
	"io/ioutil"
	"net/http"
	"runtime"
)

type server struct {
	config *Config
}

func (s *server) handleCapture(response http.ResponseWriter, request *http.Request) {
	log.Debugf("Accepted connection from %s", request.RemoteAddr)

	if request.Method != http.MethodGet {
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	appId := request.URL.Query().Get("appid")
	filter := request.URL.Query().Get("filter")
	device := request.URL.Query().Get("device")

	if appId == "" {
		response.WriteHeader(http.StatusBadRequest)
		//TODO: add some nice error message
		return
	}

	if device == "" {
		device = "eth0"
	}

	log.Debugf("Appid = %s", appId)
	log.Debugf("Filter = %s", filter)
	log.Debugf("Device = %s", device)

	// CF-SPECIFIC PARTS BEGIN
	type ContainerConfig struct {
		Handle   string `json:"handle"`
		Ip       string `json:"ip"`
		Metadata struct {
			AppId             string `json:"app_id"`
			SpaceId           string `json:"space_id,omitempty"`
			OrgId             string `json:"org_id,omitempty"`
			Ports             string `json:"ports,omitempty"`
			ContainerWorkload string `json:"container_workload,omitempty"`
			PolicyGroupId     string `json:"policy_group_id,omitempty"`
		} `json:"metadata"`
	}
	type ContainerKeys struct {
		Keys map[string]*ContainerConfig
	}

	// Load container store
	var store ContainerKeys
	storeFile := s.config.ContainerStore
	storeData, err := ioutil.ReadFile(storeFile)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		log.Errorln(err)
		return
	}

	err = json.Unmarshal(storeData, &store.Keys)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		log.Errorln(err)
		return
	}

	// Get runc container id from instance id
	var containerId string
	for key, value := range store.Keys {
		if value.Metadata.AppId == appId {
			containerId = key
		}
	}

	if containerId == "" {
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("Could not find container for instance id " + appId))
		log.Errorln(err)
		return
	}

	log.Debugf("Found container id %s for appid %s", containerId, appId)

	// Get pid from runc container state
	ctx := context.Background()
	runcClient := &runc.Runc{
		Command: s.config.RunC,
		Root:    s.config.RunCRoot,
	}

	container, err := runcClient.State(ctx, containerId)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		log.Errorln(err)
		return
	}

	pid := container.Pid

	log.Debugf("Found pid %d for container id %s", pid, containerId)

	// CF-SPECIFIC PARTS END

	// Lock the OS Thread, so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace
	origns, _ := netns.Get()
	defer origns.Close()

	// Get namespace from pid
	newns, _ := netns.GetFromPid(pid)
	defer newns.Close()

	// Activate network namespace
	err = netns.Set(newns)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		log.Errorln(err)
		return
	}
	// Switch back to the original namespace
	defer netns.Set(origns)

	// Start capturing packets
	log.Debugf("Starting capture of eth0 in netns %s of pid %d", newns, pid)
	w := pcapgo.NewWriter(response)
	err = w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		log.Errorln(err)
		return
	}
	flush(response)

	if handle, err := pcap.OpenLive(device, 65535, true, pcap.BlockForever); err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		log.Errorln(err)
		return
	} else if err := handle.SetBPFFilter(filter); err != nil { // optional
		response.WriteHeader(http.StatusInternalServerError)
		log.Errorln(err)
		return
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			log.Debugf("Pid: %d Packet: %s\n", pid, packet.String())
			err = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				if errors.Is(err, io.EOF) {
					log.Debug("Done.")
					return
				}
				response.WriteHeader(http.StatusInternalServerError)
				log.Errorln(err)
				return
			}
			flush(response)
		}
	}
}

func flush(writer io.Writer) {
	if f, ok := writer.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *server) run() {

	mux := http.NewServeMux()

	mux.HandleFunc("/capture", s.handleCapture)

	// Create a CA certificate pool and add cert.pem to it
	caCert, err := ioutil.ReadFile(s.config.CaCert)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr:      s.config.Listen,
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	// Listen to HTTPS connections with the server certificate and wait
	log.Infof("Listening on %s ...", s.config.Listen)
	log.Fatal(server.ListenAndServeTLS(s.config.Cert, s.config.Key))

}
