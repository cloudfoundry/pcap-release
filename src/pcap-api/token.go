package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	log "github.com/sirupsen/logrus"
)

// UaaKeyInfo holds the response of the UAA /token_keys endpoint
type UaaKeyInfo struct {
	Kty   string `json:"kty"`
	E     string `json:"e"`
	Use   string `json:"use"`
	Kid   string `json:"kid"`
	Alg   string `json:"alg"`
	Value string `json:"value"`
	N     string `json:"n"`
}

// verifyJWt checks the JWT token in tokenString and ensures that it's valid and contains the neededScope as claim.
// Validity is determined with the defaults, i.e.
//   - validity time range
//   - for RSA signed JWT that the RSA signature is consistent with the key provided by UAA
//   - that there is a claim 'scope' that contains one entry that matches neededScope.
//
// Limitations: only RSA signed tokens are supported.
//
// returns a boolean that confirms that the token is valid, from a valid issuer and has the needed scope,
// and an error in case anything went wrong while verifying the token and its scopes.

func VerifyJwt(tokenString string, neededScope string, issuers []string) (bool, error) {

	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if jku, ok := token.Header["jku"]; ok {
			jkuUrl, err := url.Parse(jku.(string))
			if err != nil {
				return nil, err
			}

			for _, issuer := range issuers {
				issuerUrl, err := url.Parse(issuer)
				if err != nil {
					log.Warnf("could not parse URL %s: %v", issuer, err)
					continue
				}

				if strings.HasPrefix(jkuUrl.String(), issuerUrl.String()) {
					return parseRsaToken(token)
				}
			}
			return nil, fmt.Errorf("header 'jku' %v did not match any UAA base URLs reported by the BOSH Director: %v", jku, issuers)
		}
		return nil, fmt.Errorf("header 'jku' missing from token, cannot verify signature")
	})

	if err != nil || !token.Valid {
		return false, err
	}

	if claims, claimsOk := token.Claims.(jwt.MapClaims); claimsOk {
		if scopes, ok := claims["scope"].([]interface{}); ok {
			for _, scope := range scopes {
				if scope.(string) == neededScope {
					return true, nil
				}
			}
		}
	}

	return false, fmt.Errorf("could not find scope %q in token claims", neededScope)
}

// parseRsaToken uses the token information for RSA signed JWT tokens and retrieves
// the public key information from the 'jku' header in order to retrieve key information
// (key ID, RSA public key), which is used to verify the token.
//
// Limitation: only supports RSA tokens using the 'jku' header, which points to a URL
// that can be used to retrieve key information.
func parseRsaToken(token *jwt.Token) (interface{}, error) {
	if rsa, ok := token.Method.(*jwt.SigningMethodRSA); ok {
		// with the RSA signing method, the key is a public key / certificate that can be
		// retrieved from the JKU endpoint (among other places).
		if keyInfoUrl, ok := token.Header["jku"].(string); ok {
			if kid, ok := token.Header["kid"].(string); ok {

				key, err := fetchPublicKey(keyInfoUrl, kid)
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
func fetchPublicKey(url, kid string) (*UaaKeyInfo, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				//		RootCAs:            caCertPool,
				//		Certificates:       []tls.Certificate{cert},
				//		ServerName:         s.config.AgentCommonName,

				// FIXME: Enable verify for production, provide CA
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
	}

	res, err := client.Get(url)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

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
