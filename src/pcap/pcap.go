// Package pcap provides types and interfaces to build a remote packet capturing
// tool. For details about the different applications see the different packages
// in `cmd/`.
package pcap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"unicode"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative pcap.proto

const (
	// CompatibilityLevel indicates whether two parties are compatible. Once there is a change
	// that requires both parties to be updated this value MUST be incremented by one. The calling
	// party has to ensure that the compatibility level of the called party is equal or larger and
	// refuse operation if it isn't.
	CompatibilityLevel int64 = 1

	// LogKeyVcapID sets on which field the vcap request id will be logged.
	LogKeyVcapID = "vcap-id"
	// LogKeyHandler sets the handler.
	LogKeyHandler = "handler"

	LogKeyTarget        = "target"
	LogKeyResolver      = "resolver"
	HeaderVcapID        = contextKeyVcapID("x-vcap-request-id")
	maxDeviceNameLength = 16
	maxFilterLength     = 5000
)

type contextKeyVcapID string

func (c contextKeyVcapID) String() string {
	return string(c)
}

type Stoppable interface {
	Stop()
	Wait()
}

// purge reads all messages from the given channel and discards them. The
// discarded messages are logged on the trace level.
func purge[T any](c <-chan T) {
	for m := range c {
		zap.L().Warn("draining channel: discarding message", zap.Any("message", m))
	}
}

// newMessageResponse wraps the message msg of type t into a CaptureResponse, which can be sent to the recipient.
func newMessageResponse(t MessageType, msg string, origin string) *CaptureResponse {
	return &CaptureResponse{
		Payload: &CaptureResponse_Message{
			Message: &Message{
				Type:    t,
				Message: msg,
				Origin:  origin,
			},
		},
	}
}

// newPacketResponse wraps data into a CaptureResponse, which can be sent to the recipient.
func newPacketResponse(data []byte) *CaptureResponse {
	return &CaptureResponse{
		Payload: &CaptureResponse_Packet{
			Packet: &Packet{
				Data: data,
			},
		},
	}
}

func (opts *CaptureOptions) validate() error {
	if opts.Device == "" {
		return fmt.Errorf("expected device to be not empty string")
	}

	err := validateDevice(opts.Device)
	if err != nil {
		return err
	}

	if len(opts.Filter) > maxFilterLength {
		return fmt.Errorf("expected filter to be at most %d characters, received %d", maxFilterLength, len(opts.Filter))
	}

	if opts.SnapLen == 0 {
		return fmt.Errorf("expected snaplen to be not zero")
	}
	return nil
}

// validateDevice is a go implementation of dev_valid_name from the linux kernel.
//
// See: https://lxr.linux.no/linux+v6.0.9/net/core/dev.c#L995
func validateDevice(name string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("validate device: %w", err)
		}
	}()

	if len(name) > maxDeviceNameLength {
		return fmt.Errorf("name too long: %d > %d", len(name), maxDeviceNameLength)
	}

	if name == "." || name == ".." {
		return fmt.Errorf("invalid name: '%s'", name)
	}

	for i, r := range name {
		if r == '/' {
			return fmt.Errorf("%w at pos. %d: '/'", errIllegalCharacter, i)
		}
		if r == '\x00' {
			return fmt.Errorf("%w at pos. %d: '\\0'", errIllegalCharacter, i)
		}
		if r == ':' {
			return fmt.Errorf("%w at pos. %d: ':'", errIllegalCharacter, i)
		}
		if unicode.Is(unicode.White_Space, r) {
			return fmt.Errorf("%w: whitespace at pos %d", errIllegalCharacter, i)
		}
	}

	return nil
}

// setVcapID expands log to include the vcap-id extracted from ctx, if available.
// When no vcap-id is defined in ctx, a new random GUID is generated and add to context key HeaderVcapID and the logger.
func setVcapID(ctx context.Context, log *zap.Logger, externalVcapID *string) (context.Context, *zap.Logger) {
	vcapID, err := vcapIDFromIncomingCtx(ctx)

	if err != nil {
		if errors.Is(err, errNoVcapID) {
			log.Warn("request does not contain request id, generating one")
		}

		if externalVcapID != nil {
			vcapID = externalVcapID
		} else {
			// No existing vcap-id found, creating a new one and adding it to the context.
			newVcapID := uuid.Must(uuid.NewRandom()).String()
			vcapID = &newVcapID
		}
	}
	ctx = context.WithValue(ctx, HeaderVcapID, *vcapID)

	log = log.With(zap.String(LogKeyVcapID, *vcapID))

	return ctx, log
}

// vcapIDFromIncomingCtx finds the vcap-id from the context metadata, if available.
//
// returns errNoVcapID if no vcap-id was found in the metadata.
func vcapIDFromIncomingCtx(ctx context.Context) (*string, error) {
	var vcap *string
	var err error
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		vcap, err = getVcapFromMD(md)
		if err == nil {
			return vcap, nil
		}
	}
	return nil, errNoVcapID
}

func getVcapFromMD(md metadata.MD) (*string, error) {
	vcapReqIDs := md.Get(HeaderVcapID.String())

	if len(vcapReqIDs) > 0 {
		vcapID := vcapReqIDs[0]
		return &vcapID, nil
	}
	return nil, errNoVcapID
}

// interfaceAddrs provides a list of all known network addresses.
var interfaceAddrs = net.InterfaceAddrs

// containsForbiddenRunes checks whether a given string contains
// any character that is less than 32 or more than 126.
//
// See: https://www.lookuptables.com/text/ascii-table
func containsForbiddenRunes(in string) bool {
	for _, r := range in {
		if r < 32 || r > 126 {
			return true
		}
	}
	return false
}

// patchFilter extends the given filter by excluding the filter generated
// by generateApiFilter.
func patchFilter(filter string) (string, error) {
	apiFilter, err := generateAPIFilter()
	if err != nil {
		return "", err
	}

	filter = strings.TrimSpace(filter)

	if filter == "" {
		return fmt.Sprintf("not (%s)", apiFilter), nil
	}

	return fmt.Sprintf("not (%s) and (%s)", apiFilter, filter), nil
}

// generateApiFilter takes all IP addresses as returned by interfaceAddrs and
// generates a filter for those IP addresses (loopback is excluded from the filter).
// Note: the filter *matches* all of those IP addresses.
func generateAPIFilter() (string, error) {
	addrs, err := interfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("unable to get IPs: %w", err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("unable to determine ip addresses")
	}

	var ipFilters []string
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		// check that:
		// * ipNet is actually an IP address
		// * it is not a loopback address
		// * can be represented in either 4- or 16-bytes representation
		if ok && !ipNet.IP.IsLoopback() {
			// Check whether the IP is v4 or v6. If both evaluate to true
			// v4 takes precedence.
			var expression string
			switch {
			case ipNet.IP.To4() != nil:
				expression = "ip"
			case ipNet.IP.To16() != nil:
				expression = "ip6"
			default:
				return "", fmt.Errorf("address %s is not IPv4 or v6", ipNet.IP.String())
			}

			ipFilters = append(ipFilters, fmt.Sprintf("%s host %s", expression, ipNet.IP.String()))
		}
	}
	return strings.Join(ipFilters, " or "), nil
}

// makeStopRequest creates the generic stop CaptureRequest that can be sent to api and agent.
func makeStopRequest() *CaptureRequest {
	return &CaptureRequest{Operation: &CaptureRequest_Stop{Stop: &StopCapture{}}}
}

// forwardToStream reads Packets from src until it's closed and writes them to stream.
// If it encounters an error while doing so the error is set to cause and the cancel function
// is called. Any data left in src is discarded after a write-error occurred.
func forwardToStream(cancel CancelCauseFunc, src <-chan *CaptureResponse, stream responseSender, bufConf BufferConf, wg *sync.WaitGroup, id string) {
	go func() {
		// After this function returns we want to make sure that this channel is
		// drained properly if there is anything left in it. This avoids responses
		// left after the connection to the client broke and no more responses are
		// read from the channel.
		defer purge(src)
		defer wg.Done()

		discarding := false
		for res := range src {
			// we never discard messages, only data
			_, isMsg := res.Payload.(*CaptureResponse_Message)

			// example (values are probably a bad choice):
			// buffer size: 10
			// lower limit: 2
			// upper limit: 8
			// len(src)      => fill level of buffer
			// discarding    => are we currently discarding packet responses?
			// messages sent => how many messages have been sent up until now
			// len(src) | discarding | messages sent
			// 2        | false      | 0
			// 1        | false      | 1
			// 7        | false      | 2
			// 6        | false      | 3
			// 9        | true       | 4 // last packet was DISCARDING_MESSAGES
			// 8        | true       | 4
			// 7        | true       | 4
			// ...
			// 3        | true       | 4
			// 2        | false      | 5
			// 1        | false      | 6

			switch {
			case len(src) <= bufConf.LowerLimit: // if buffer size is zero this case will always match
				discarding = false
			case discarding && !isMsg:
				continue
			case len(src) >= bufConf.UpperLimit && !isMsg:
				discarding = true
				// this only is sent when we start discarding (and discards the current data packet)
				res = newMessageResponse(MessageType_CONGESTED, "too much back pressure, discarding packets", id)
			}

			err := stream.Send(res)
			if err != nil {
				cancel(errorf(codes.Unknown, "send response: %w", err))
				return
			}
		}
		cancel(errorf(codes.Aborted, "no data is left to forward"))
	}()
}

// LoadTLSCredentials creates TLS transport credentials from the given parameters.
func LoadTLSCredentials(certFile, keyFile string, caFile *string, peerCAFile *string, peerCommonName *string) (credentials.TransportCredentials, error) {
	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate or private key failed: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{cert}
	}

	if caFile != nil {
		caPool, err := createCAPool(*caFile)
		if err != nil {
			return nil, fmt.Errorf("load certificate authority file failed: %w", err)
		}
		tlsConf.ClientCAs = caPool
	}

	if peerCAFile != nil {
		caPool, err := createCAPool(*peerCAFile)
		if err != nil {
			return nil, fmt.Errorf("load certificate authority file failed: %w", err)
		}
		tlsConf.RootCAs = caPool
	}

	if peerCommonName != nil {
		tlsConf.ServerName = *peerCommonName
	}

	return credentials.NewTLS(tlsConf), nil
}

func createCAPool(certificateAuthorityFile string) (*x509.CertPool, error) {
	caFile, err := os.ReadFile(certificateAuthorityFile)
	if err != nil {
		return nil, err
	}

	caPool := x509.NewCertPool()

	// We do not use x509.CertPool.AppendCertsFromPEM because it swallows any errors.
	// We would like to now if any certificate failed (and not just if any certificate
	// could be parsed).
	for len(caFile) > 0 {
		var block *pem.Block

		block, caFile = pem.Decode(caFile)
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("ca file contains non-certificate blocks")
		}

		ca, caErr := x509.ParseCertificate(block.Bytes)
		if caErr != nil {
			return nil, caErr
		}

		caPool.AddCert(ca)
	}
	return caPool, nil
}
