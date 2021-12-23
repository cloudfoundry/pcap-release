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

	if request.Method != http.MethodGet {
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	instanceId := request.URL.Query().Get("instanceid")
	filter := request.URL.Query().Get("filter")
	device := "eth0"

	if instanceId == "" {
		response.WriteHeader(http.StatusBadRequest)
		//TODO: add some nice error message
		return
	}

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
		if value.Metadata.AppId == instanceId {
			containerId = key
		}
	}

	if containerId == "" {
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("Could not find container for instance id " + instanceId))
		log.Errorln(err)
		return
	}

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
	w := pcapgo.NewWriter(response)
	err = w.WriteFileHeader(1600, layers.LinkTypeEthernet)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		log.Errorln(err)
		return
	}

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
					return
				}
				response.WriteHeader(http.StatusInternalServerError)
				log.Errorln(err)
				return
			}
		}
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
	log.Fatal(server.ListenAndServeTLS(s.config.Cert, s.config.Key))

}
