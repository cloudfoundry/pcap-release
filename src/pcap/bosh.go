package pcap

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
)

var BoshResolverName = "bosh"

// BoshInfo corresponds to the relevant data that is provided as JSON from the BOSH Director
// endpoint /info. This struct is limited to the fields needed for the supported operation types (i.e. using UAA).
type BoshInfo struct {
	Name            string `json:"name"`
	UUID            string `json:"uuid"`
	Version         string `json:"version"`
	Cpi             string `json:"cpi"`
	StemcellOS      string `json:"stemcell_os"`
	StemcellVersion string `json:"stemcell_version"`

	UserAuthentication struct {
		Type    string `json:"type"`
		Options struct {
			URL  string   `json:"url"`
			URLs []string `json:"urls"`
		} `json:"options"`
	} `json:"user_authentication"`
}

// BoshInstance contains the metadata about a particular BOSH VM instance in a BOSH deployment.
type BoshInstance struct {
	AgentID     string    `json:"agent_id"`
	Cid         string    `json:"cid"`
	Job         string    `json:"job"`
	Index       int       `json:"index"`
	ID          string    `json:"id"`
	Az          string    `json:"az"`
	Ips         []string  `json:"ips"`
	VMCreatedAt time.Time `json:"vm_created_at"`
	ExpectsVM   bool      `json:"expects_vm"`
}

// BoshResolverConfig defines the configuration for a specific BOSH environment used for a BoshResolver.
type BoshResolverConfig struct {
	RawDirectorURL string     `yaml:"director_url" validate:"required,url"`
	AgentPort      int        `yaml:"agent_port" validate:"required,gt=0,lte=65535"`
	TokenScope     string     `yaml:"token_scope" validate:"required"`
	TLS            *ClientTLS `yaml:"tls" validate:"omitempty"`
}

// BoshResolver uses a BOSH director to resolve AgentEndpoint s.
//
// Must call setup() to initialize. This is done by NewBoshResolver(), which is the preferred way of initialization.
type BoshResolver struct {
	client      *http.Client
	UaaURLs     []string
	Config      BoshResolverConfig
	DirectorURL *url.URL
	logger      *zap.Logger
	tlsConf     *tls.Config
}

// NewBoshResolver creates and initializes a BoshResolver based on the provided config.
// NewBoshResolver calls setup() to establish the connection to the configured BOSH Director.
//
// Returns an error if the configuration is incorrect (unparseable URL, incorrect or inconsistent TLS configuration)
// or the connection to the BOSH director fails.
func NewBoshResolver(config BoshResolverConfig) (*BoshResolver, error) {
	directorURL, err := url.Parse(config.RawDirectorURL)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize BoshResolver for URL %s: %w", config.RawDirectorURL, err)
	}

	// Workaround for URL.JoinPath, which is buggy: https://github.com/golang/go/issues/58605
	if directorURL.Path == "" {
		directorURL.Path = "/"
	}

	resolver := &BoshResolver{
		logger:      zap.L().With(zap.String(LogKeyHandler, BoshResolverName)),
		Config:      config,
		DirectorURL: directorURL,
	}

	if config.TLS != nil {
		resolver.tlsConf, err = config.TLS.Config()
		if err != nil {
			return nil, err
		}
	}

	err = resolver.setup()
	if err != nil {
		return nil, err
	}
	return resolver, err
}

func (br *BoshResolver) Name() string {
	return BoshResolverName
}

func (br *BoshResolver) CanResolve(request *EndpointRequest) bool {
	if request == nil {
		return false
	}

	return request.GetBosh() != nil
}

// Resolve returns applicable AgentEndpoint s for request
//
// Fails if:
//   - the token could not be verified
//   - no endpoints match the query.
//
// No endpoints are found if:
//   - none of the instance groups in the request have instances or the instance groups are not found
//   - the provided instance IDs don't match any of the existing ID in selected instance groups
func (br *BoshResolver) Resolve(request *EndpointRequest, logger *zap.Logger) ([]AgentEndpoint, error) {
	logger.Info("resolving endpoints for bosh request")

	err := br.Validate(request)
	if err != nil {
		return nil, err
	}

	boshRequest := request.GetBosh()

	err = br.Authenticate(boshRequest.Token)
	if err != nil {
		return nil, err
	}

	instances, err := br.getInstances(boshRequest.Deployment, boshRequest.Token)
	if err != nil {
		return nil, err
	}

	var endpoints []AgentEndpoint
	for _, instance := range instances {
		if !matchesInstanceGroups(instance, boshRequest.Groups) {
			continue
		}

		if len(boshRequest.Instances) > 0 && !matchesInstanceIDs(instance, boshRequest.Instances) {
			continue
		}

		identifier := strings.Join([]string{instance.Job, instance.ID}, "/")
		endpoints = append(endpoints, AgentEndpoint{
			IP: instance.Ips[0], Port: br.Config.AgentPort, Identifier: identifier,
		})
	}

	if len(endpoints) == 0 {
		return nil, ErrNoEndpoints
	}

	logger.Debug("received AgentEndpoints from Bosh Director", zap.Any("agent-endpoint", endpoints))
	return endpoints, nil
}

// matchesInstanceGroups determines whether the instance matches one of the selected groups.
func matchesInstanceGroups(instance BoshInstance, groups []string) bool {
	for _, validGroup := range groups {
		if instance.Job == validGroup {
			return true
		}
	}
	return false
}

// matchesInstanceGroups determines whether the instance matches one of the selected instance IDs.
func matchesInstanceIDs(instance BoshInstance, ids []string) bool {
	for _, validID := range ids {
		if instance.ID == validID {
			return true
		}
	}
	return false
}

func (br *BoshResolver) Validate(endpointRequest *EndpointRequest) error {
	boshRequest := endpointRequest.GetBosh()

	if boshRequest == nil {
		return fmt.Errorf("invalid bosh request: %w", errNilField)
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

// setup is called in NewBoshResolver and ensures that a connection to the configured BOSH director is possible.
// Retrieves information about the director and its UAA.
//
// Returns an error if the connection to the BOSH Director is not possible.
func (br *BoshResolver) setup() error {
	br.logger.Debug("setting up BoshResolver", zap.Any("resolver-config", br.Config))

	timeout := 500 * time.Millisecond //nolint:gomnd // reasonable value.

	br.client = &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			ExpectContinueTimeout: timeout,
			DisableKeepAlives:     true,
			MaxIdleConnsPerHost:   -1,
			TLSClientConfig:       br.tlsConf,
		},
		Timeout: timeout,
	}

	br.logger.Debug("discovering bosh-UAA endpoint", zap.String("bosh-director", br.DirectorURL.String()))
	apiResponse, err := br.info()
	if err != nil {
		return err
	}

	br.UaaURLs = apiResponse.UserAuthentication.Options.URLs
	br.logger.Info("connected to bosh-director", zap.Any("bosh-director", br.DirectorURL.String()))
	return nil
}

// info retrieves the BOSH director /info endpoint.
//
// Used for startup and health check.
//
// Returns an error if the connection to the director URL fails or the response from the director is not a BoshInfo.
func (br *BoshResolver) info() (*BoshInfo, error) {
	infoEndpoint := br.DirectorURL.JoinPath("/info")

	response, err := br.client.Do(&http.Request{
		Method: http.MethodGet,
		URL:    infoEndpoint,
	})
	if err != nil {
		return nil, fmt.Errorf("could not fetch Bosh Director API from %v: %w", br.Config.RawDirectorURL, err)
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-OK response from Bosh Director: %s", response.Status)
	}

	var apiResponse BoshInfo
	err = json.NewDecoder(response.Body).Decode(&apiResponse)
	if err != nil {
		return nil, fmt.Errorf("could not parse bosh-director API response: %w", err)
	}
	return &apiResponse, nil
}

// Healthy returns true if the resolver can retrieve /info to the BOSH director.
func (br *BoshResolver) Healthy() bool {
	_, err := br.info()
	return err == nil
}

func (br *BoshResolver) Authenticate(authToken string) error {
	err := br.verifyJWT(authToken)
	if err == nil {
		return nil
	}

	if errors.Is(err, ErrNotAuthorized) {
		return fmt.Errorf("token %s does not have the permissions or is not supported: %w", authToken, err)
	}
	return fmt.Errorf("could not verify token: %w", err)
}

// getInstances retrieves all instances for deployment using authToken.
//
// Returns an error if the resolver is not connected to BOSH, the request to BOSH failed.
func (br *BoshResolver) getInstances(deployment string, authToken string) ([]BoshInstance, error) {
	if br.client == nil {
		return nil, ErrBoshNotConnected
	}
	br.logger.Debug("checking token-permissions", zap.String("director-url", br.DirectorURL.String()), zap.String("deployment", deployment))
	instancesURL, err := url.Parse(fmt.Sprintf("%s/deployments/%s/instances", br.DirectorURL, deployment))
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodGet,
		URL:    instancesURL,
		Header: map[string][]string{
			"Authorization": {"Bearer " + authToken},
		},
	}

	res, err := br.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to Bosh-director failed: %w", err)
	}

	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		data, dataReadErr := io.ReadAll(res.Body)
		if dataReadErr != nil {
			return nil, fmt.Errorf("failed reading data of non-OK response, status %d: %w", res.StatusCode, dataReadErr)
		}
		return nil, fmt.Errorf("expected status code %d but got status code %d. received body: %s", http.StatusOK, res.StatusCode, string(data))
	}

	var response []BoshInstance

	err = json.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// UaaKeyInfo holds the response of the UAA /token_keys endpoint.
type UaaKeyInfo struct {
	Kty   string `json:"kty"`
	E     string `json:"e"`
	Use   string `json:"use"`
	Kid   string `json:"kid"`
	Alg   string `json:"alg"`
	Value string `json:"value"`
	N     string `json:"n"`
}

// verifyJWT checks the JWT token in tokenString and ensures that it's valid and contains the neededScope as claim.
//
// Validity is determined with the defaults, i.e.:
//   - validity time range
//   - for RSA signed JWT that the RSA signature is consistent with the key provided by UAA
//   - that there is a claim 'scope' that contains one entry that matches neededScope.
//
// Limitations: only RSA signed tokens are supported.
//
// Returns a boolean that confirms that the token is valid, from a valid issuer and has the needed scope,
// and an error in case anything went wrong while verifying the token and its scopes.
func (br *BoshResolver) verifyJWT(tokenString string) error {
	token, err := jwt.Parse(tokenString, br.parseKey)

	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("token invalid")
	}

	claims, claimsOk := token.Claims.(jwt.MapClaims)

	if !claimsOk {
		return fmt.Errorf("token did not contain claims, required scope %q: %w", br.Config.TokenScope, ErrNotAuthorized)
	}

	scopes, ok := claims["scope"].([]interface{})
	if ok {
		for _, scope := range scopes {
			if scope.(string) == br.Config.TokenScope {
				return nil
			}
		}
	}

	return fmt.Errorf("could not find scope %q in token claims: %w", br.Config.TokenScope, ErrNotAuthorized)
}

// parseKey attempts to find the appropriate signing key for the token based on the information provided with the token.
//
// called by jwt.Parse().
//
// Returns the identified signing key or an error. The key type interface{} is enforced by jwt.Keyfunc.
func (br *BoshResolver) parseKey(token *jwt.Token) (interface{}, error) {
	jku, ok := token.Header["jku"]

	if !ok {
		return nil, fmt.Errorf("header 'jku' missing from token, cannot verify signature: %w", ErrTokenUnsupported)
	}

	jkuURL, err := url.Parse(jku.(string))
	if err != nil {
		return nil, err
	}

	for _, issuer := range br.UaaURLs {
		var issuerURL *url.URL
		issuerURL, err = url.Parse(issuer)
		if err != nil {
			br.logger.Warn("could not parse URL", zap.String("issuer", issuer), zap.Error(err))
			continue
		}

		if strings.HasPrefix(jkuURL.String(), issuerURL.String()) {
			return br.parseRsaToken(token)
		}
	}
	return nil, fmt.Errorf("header 'jku' %v did not match any UAA base URLs reported by the BOSH Director: %v: %w", jku, br.UaaURLs, ErrNotAuthorized)
}

// parseRsaToken uses the token information for RSA signed JWT tokens and retrieves
// the public key information from the 'jku' header in order to retrieve key information
// (key ID, RSA public key), which is used to verify the token.
//
// Limitation: only supports RSA tokens using the 'jku' header, which points to a URL
// that can be used to retrieve key information.
func (br *BoshResolver) parseRsaToken(token *jwt.Token) (*rsa.PublicKey, error) {
	signingMethodRSA, ok := token.Method.(*jwt.SigningMethodRSA)

	if !ok {
		return nil, fmt.Errorf("unsupported signing method: %v: %w", token.Header["alg"], ErrTokenUnsupported)
	}

	// with the RSA signing method, the key is a public key / certificate that can be
	// retrieved from the JKU endpoint (among other places).
	key, done, err := br.verifyRSASignature(token, signingMethodRSA)
	if done {
		return key, err
	}

	return nil, fmt.Errorf("could not find key information URL in token headers: %+v: %w", token.Header, ErrTokenUnsupported)
}

func (br *BoshResolver) verifyRSASignature(token *jwt.Token, rsa *jwt.SigningMethodRSA) (*rsa.PublicKey, bool, error) {
	rawKeyInfoURL, ok := token.Header["jku"].(string)

	if !ok {
		return nil, false, fmt.Errorf("token does not contain jku: %w", ErrNotAuthorized)
	}
	var kid string
	if kid, ok = token.Header["kid"].(string); ok {
		return br.getPublicKeyPEM(rawKeyInfoURL, kid, rsa)
	}

	return nil, false, fmt.Errorf("token does not contain kid: %w", ErrNotAuthorized)
}

func (br *BoshResolver) getPublicKeyPEM(rawKeyInfoURL string, kid string, rsa *jwt.SigningMethodRSA) (*rsa.PublicKey, bool, error) {
	keyInfoURL, err := url.Parse(rawKeyInfoURL)
	if err != nil {
		return nil, true, err
	}

	key, err := br.fetchPublicKey(keyInfoURL, kid)
	if err != nil {
		return nil, true, err
	}

	if rsa.Alg() != key.Alg {
		return nil, true, fmt.Errorf("signature algorithm %q does not match expected token key information %q: %w", rsa.Alg(), key.Alg, ErrNotAuthorized)
	}

	// the RSA public key returned here is used to check the JWT token signature.
	// It is provided by the URL encoded in the token (in the 'jku' header).
	// For valid tokens, this URL is verified against the UAA URLs reported by BOSH Director later.
	pem, pemError := jwt.ParseRSAPublicKeyFromPEM([]byte(key.Value))
	if pemError != nil {
		return nil, false, pemError
	}
	return pem, true, nil
}

// fetchPublicKey fetches the token key information from url and returns the key with the Key ID (kid).
//
// Returns an error if no key can be found with the requested kid or an error arises while communicating with url.
//
// Limitation: This will only fetch the first key with RSA as signature algorithm.
func (br *BoshResolver) fetchPublicKey(url *url.URL, kid string) (*UaaKeyInfo, error) {
	res, err := br.client.Do(&http.Request{
		Method: http.MethodGet,
		URL:    url,
	})
	if err != nil {
		return nil, err
	}

	defer func() { _ = res.Body.Close() }()

	keys := struct {
		Keys []UaaKeyInfo
	}{}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &keys)
	if err != nil {
		return nil, err
	}

	for _, key := range keys.Keys {
		if key.Kty == "RSA" && key.Kid == kid {
			return &key, nil
		}
	}

	return nil, fmt.Errorf("key info of type RSA for kid %q not found in token keys endpoint: %w", kid, ErrNotAuthorized)
}
