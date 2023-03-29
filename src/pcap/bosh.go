package pcap

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
)

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

type BoshResolverConfig struct {
	RawDirectorURL   string     `yaml:"director_url" validate:"required,url"`
	EnvironmentAlias string     `yaml:"alias" validate:"required"`
	AgentPort        int        `yaml:"agent_port" validate:"required,gt=0,lte=65535"`
	TokenScope       string     `yaml:"token_scope" validate:"required"`
	MTLS             *MutualTLS `yaml:"mtls" validate:"omitempty"`
}

type BoshResolver struct {
	client      *http.Client
	uaaURLs     []string
	config      BoshResolverConfig
	directorURL *url.URL
	logger      *zap.Logger
	boshRootCAs *x509.CertPool
}

func NewBoshResolver(config BoshResolverConfig) (*BoshResolver, error) {
	directorURL, err := url.Parse(config.RawDirectorURL)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize BoshResolver for environment %s. %w", config.EnvironmentAlias, err)
	}

	var boshRootCAs *x509.CertPool
	if config.MTLS != nil {
		boshRootCAs, err = createCAPool(config.MTLS.CertificateAuthority)
		if err != nil {
			return nil, fmt.Errorf("could not create bosh CA pool: %w", err)
		}
	}

	resolver := &BoshResolver{
		logger:      zap.L().With(zap.String(LogKeyHandler, config.EnvironmentAlias)),
		config:      config,
		directorURL: directorURL,
		boshRootCAs: boshRootCAs,
	}

	err = resolver.setup()
	if err != nil {
		return nil, err
	}
	return resolver, err
}

func (br *BoshResolver) Name() string {
	return fmt.Sprintf("bosh/%s", br.config.EnvironmentAlias)
}

func (br *BoshResolver) CanResolve(request *EndpointRequest) bool {
	if request == nil {
		return false
	}

	if boshRequest := request.GetBosh(); boshRequest != nil {
		return boshRequest.Environment == br.config.EnvironmentAlias
	}
	return false
}

func (br *BoshResolver) Resolve(request *EndpointRequest, logger *zap.Logger) ([]AgentEndpoint, error) { // TODO why do we pass the logger here?
	logger.Info("resolving endpoints for bosh request")

	err := br.validate(request)
	if err != nil {
		return nil, err
	}

	boshRequest := request.GetBosh()

	err = br.authenticate(boshRequest.Token)
	if err != nil {
		return nil, err
	}

	instances, _, err := br.getInstances(boshRequest.Deployment, boshRequest.Token)
	if err != nil {
		return nil, err
	}

	var endpoints []AgentEndpoint
	for _, instance := range instances {
		identifier := strings.Join([]string{instance.Job, instance.ID}, "/")
		endpoints = append(endpoints, AgentEndpoint{IP: instance.Ips[0], Port: br.config.AgentPort, Identifier: identifier})
	}

	if len(endpoints) == 0 {
		return nil, errNoEndpoints
	}

	logger.Debug("received AgentEndpoints from Bosh Director", zap.Any("agent-endpoint", endpoints))
	return endpoints, nil
}

func (br *BoshResolver) validate(endpointRequest *EndpointRequest) error {
	boshRequest := endpointRequest.GetBosh()

	if boshRequest == nil {
		return fmt.Errorf("invalid message: br: %w", errNilField)
	}

	if boshRequest.Token == "" {
		return fmt.Errorf("invalid message: token: %w", errEmptyField)
	}

	if boshRequest.Deployment == "" {
		return fmt.Errorf("invalid message: deployment: %w", errEmptyField)
	}

	if boshRequest.Environment == "" {
		return fmt.Errorf("invalid message: environment: %w", errEmptyField)
	}

	if len(boshRequest.Groups) == 0 {
		return fmt.Errorf("invalid message: instance group(s): %w", errEmptyField)
	}

	return nil
}

func (br *BoshResolver) setup() error {
	br.logger.Info("setting up BoshResolver", zap.Any("resolver-config", br.config))

	if br.config.MTLS == nil {
		br.client = http.DefaultClient
	} else {
		br.client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					MaxVersion: tls.VersionTLS13,
					ClientAuth: tls.RequireAndVerifyClientCert,
					RootCAs:    br.boshRootCAs,
				},
			},
		}
	}

	br.logger.Info("discovering bosh-UAA endpoint")
	ptr := *br.directorURL
	infoEndpoint := &ptr
	infoEndpoint.Path = "/info"
	//TODO: (discussion) weird. br.directorURL.JoinPath("/info") is buggy: https://github.com/golang/go/issues/58605

	response, err := br.client.Do(&http.Request{
		Method: http.MethodGet,
		URL:    infoEndpoint,
	})
	if err != nil {
		return fmt.Errorf("could not fetch bosh-director API from %v: %w", br.config.RawDirectorURL, err)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-OK response from bosh-director: %s", response.Status)
	}

	defer CloseQuietly(response.Body)

	var apiResponse *BoshInfo
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("could not read bosh-director API response: %w", err)
	}
	err = json.Unmarshal(data, &apiResponse)
	if err != nil {
		return fmt.Errorf("could not parse bosh-director API response: %w", err)
	}

	br.uaaURLs = apiResponse.UserAuthentication.Options.URLs

	br.logger.Info("connected to bosh-director", zap.Any("bosh-director", apiResponse))

	return nil
}

func (br *BoshResolver) authenticate(authToken string) error {
	allowed, err := br.verifyJWT(authToken)
	if err != nil {
		return fmt.Errorf("could not verify token: %w", err)
	}

	if !allowed {
		return fmt.Errorf("token %s does not have the permissions or is not supported", authToken)
	}

	return nil
}

func (br *BoshResolver) getInstances(deployment string, authToken string) ([]BoshInstance, int, error) {
	br.logger.Debug("checking token-permissions", zap.String("director-url", br.directorURL.String()), zap.String("deployment", deployment))
	instancesURL, err := url.Parse(fmt.Sprintf("%s/deployments/%s/instances", br.directorURL, deployment))
	if err != nil {
		return nil, 0, err
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
		return nil, 0, fmt.Errorf("request to Bosh-director failed: %v", zap.Error(err))
	}

	defer CloseQuietly(res.Body)

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, res.StatusCode, fmt.Errorf("expected status code %d but got status code %d: %s", http.StatusOK, res.StatusCode, string(data))
	}

	var response []BoshInstance

	err = json.Unmarshal(data, &response)
	if err != nil {
		return nil, 0, err
	}

	return response, res.StatusCode, nil
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
// Validity is determined with the defaults, i.e.
//   - validity time range
//   - for RSA signed JWT that the RSA signature is consistent with the key provided by UAA
//   - that there is a claim 'scope' that contains one entry that matches neededScope.
//
// Limitations: only RSA signed tokens are supported.
//
// returns a boolean that confirms that the token is valid, from a valid issuer and has the needed scope,
// and an error in case anything went wrong while verifying the token and its scopes.
func (br *BoshResolver) verifyJWT(tokenString string) (bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if jku, ok := token.Header["jku"]; ok {
			jkuURL, err := url.Parse(jku.(string))
			if err != nil {
				return nil, err
			}

			for _, issuer := range br.uaaURLs {
				var issuerURL *url.URL
				issuerURL, err = url.Parse(issuer)
				if err != nil {
					br.logger.Warn("could not parse URL %s: %v", zap.String("issuer", issuer), zap.Error(err))
					continue
				}

				if strings.HasPrefix(jkuURL.String(), issuerURL.String()) {
					return br.parseRsaToken(token)
				}
			}
			return nil, fmt.Errorf("header 'jku' %v did not match any UAA base URLs reported by the BOSH Director: %v", jku, br.uaaURLs)
		}
		return nil, fmt.Errorf("header 'jku' missing from token, cannot verify signature")
	})

	if err != nil || !token.Valid {
		return false, err
	}

	if claims, claimsOk := token.Claims.(jwt.MapClaims); claimsOk {
		if scopes, ok := claims["scope"].([]interface{}); ok {
			for _, scope := range scopes {
				if scope.(string) == br.config.TokenScope {
					return true, nil
				}
			}
		}
	}

	return false, fmt.Errorf("could not find scope %q in token claims", br.config.TokenScope)
}

// parseRsaToken uses the token information for RSA signed JWT tokens and retrieves
// the public key information from the 'jku' header in order to retrieve key information
// (key ID, RSA public key), which is used to verify the token.
//
// Limitation: only supports RSA tokens using the 'jku' header, which points to a URL
// that can be used to retrieve key information.
func (br *BoshResolver) parseRsaToken(token *jwt.Token) (interface{}, error) {
	if rsa, ok := token.Method.(*jwt.SigningMethodRSA); ok {
		// with the RSA signing method, the key is a public key / certificate that can be
		// retrieved from the JKU endpoint (among other places).
		if rawKeyInfoURL, ok := token.Header["jku"].(string); ok {
			var kid string
			if kid, ok = token.Header["kid"].(string); ok {
				keyInfoURL, err := url.Parse(rawKeyInfoURL)
				if err != nil {
					return nil, err
				}

				key, err := br.fetchPublicKey(keyInfoURL, kid)
				if err != nil {
					return nil, err
				}

				if rsa.Alg() != key.Alg {
					return nil, fmt.Errorf("signature algorithm %q does not match expected token key information %q", rsa.Alg(), key.Alg)
				}

				// the RSA public key returned here is used to check the JWT token signature.
				// It is provided by the URL encoded in the token (in the 'jku' header).
				// For valid tokens, this URL is verified against the UAA URLs reported by BOSH Director later.
				return jwt.ParseRSAPublicKeyFromPEM([]byte(key.Value))
			}
		}

		return nil, fmt.Errorf("could not find key information URL in token headers: %+v", token.Header)
	}

	return nil, fmt.Errorf("unsupported signing method: %v", token.Header["alg"])
}

// fetchPublicKey fetches the token key information from url and returns the key with the Key ID (kid).
//
// returns an error if no key can be found with the requested kid or an error arises while communicating with url.
//
// Limitation: This will only fetch keys with RSA as signature algorithm.
func (br *BoshResolver) fetchPublicKey(url *url.URL, kid string) (*UaaKeyInfo, error) {

	res, err := br.client.Do(&http.Request{
		Method: http.MethodGet,
		URL:    url,
	})
	if err != nil {
		return nil, err
	}

	defer CloseQuietly(res.Body)

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
			matchingKey := key
			return &matchingKey, nil
		}
	}

	return nil, fmt.Errorf("key info of type RSA for kid %q not found in token keys endpoint", kid)
}
