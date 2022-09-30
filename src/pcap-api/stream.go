package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
)

type PcapStreamer struct {
	config *Config
}

func NewCaptureStreamer(config *Config) *PcapStreamer {
	return &PcapStreamer{config: config}
}

// getPcapStream requests and retrieves a pcap capture from the agent using the pcapAgentURL.
// the pcapAgentURL contains information on what to capture.
func (s *PcapStreamer) getPcapStream(pcapAgentURL string) (io.ReadCloser, error) {
	log.Debugf("Getting pcap stream from %s", pcapAgentURL)
	cert, err := tls.LoadX509KeyPair(s.config.ClientCert, s.config.ClientCertKey)
	if err != nil {
		return nil, err
	}

	caCert, err := os.ReadFile(s.config.AgentCa)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				Certificates:       []tls.Certificate{cert},
				ServerName:         s.config.AgentCommonName,
				InsecureSkipVerify: s.config.AgentTlsSkipVerify, //nolint:gosec
			},
		},
	}

	res, err := client.Get(pcapAgentURL)

	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return res.Body, fmt.Errorf("expected status code %d but got status code %d", http.StatusOK, res.StatusCode)
	}

	return res.Body, nil
}

type packetMessage struct {
	packet gopacket.Packet
	done   bool
	err    error
}

// captureAndStream invokes the pcap-agents in captureURLs in parallel (using captureFromAgent()) and multiplexes the results into the response writer.
func (s *PcapStreamer) captureAndStream(captureURLs []string, response *http.ResponseWriter, request *http.Request) {

	packets := make(chan packetMessage, 1000)

	for _, agentURL := range captureURLs {
		go s.captureFromAgent(agentURL, packets)
	}

	// Collect all packets from multiple input streams and merge them into one output stream
	w := pcapgo.NewWriter(*response)
	err := w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	if err != nil {
		log.Error(err)
		return
	}

	bytesTotal := 24 // pcap header is 24 bytes
	done := 0
	for msg := range packets {
		if msg.packet != nil {
			err = w.WritePacket(msg.packet.Metadata().CaptureInfo, msg.packet.Data())
			if err != nil {
				handleIOError(err)
				return
			}
			bytesTotal += msg.packet.Metadata().Length
			if f, ok := (*response).(http.Flusher); ok {
				f.Flush()
			}
		}
		if msg.done {
			done++
			if done == len(captureURLs) {
				log.Infof("Done capturing. Wrote %d bytes from %s to %s", bytesTotal, request.URL, request.RemoteAddr)
				return
			}
		}
	}
}

// captureFromAgent retrieves the pcap data from the agent using agentURL via getPcapStream() and sends the received pcap data into the channel packets.
func (s *PcapStreamer) captureFromAgent(agentURL string, packets chan packetMessage) {
	defer func() {
		packets <- packetMessage{
			packet: nil,
			done:   true,
		}
	}()
	pcapStream, err := s.getPcapStream(agentURL)
	if err != nil {
		log.Errorf("could not get pcap stream from URL %s (%s)", agentURL, err)
		packets <- packetMessage{
			packet: nil,
			done:   true,
			err:    err,
		}
		return
	}

	defer pcapStream.Close()

	// Stream the pcap back to the client
	pcapReader, err := pcapgo.NewReader(pcapStream)
	if err != nil {
		captureError := fmt.Errorf("could not create pcap reader from pcap stream %s (%s)", pcapStream, err)
		packets <- packetMessage{
			err: captureError,
		}

		return
	}

	for {
		data, capInfo, err := pcapReader.ReadPacketData()
		if err != nil {
			handleIOError(err)
			return
		}
		log.Debugf("Read packet: Time %s Length %d Captured %d", capInfo.Timestamp, capInfo.Length, capInfo.CaptureLength)
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		packet.Metadata().CaptureInfo = capInfo
		packets <- packetMessage{
			packet: packet,
			done:   false,
		}
	}
}

func handleIOError(err error) {
	if errors.Is(err, io.EOF) {
		log.Debug("Done capturing.")
	} else {
		log.Errorf("Error during capture: %s", err)
	}
}
