package bosh

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"
)

type Config struct {
	Environments []Environment `yaml:"environments"`
}

type Instance struct {
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

type Info struct {
	Name               string      `json:"name"`
	Uuid               string      `json:"uuid"`
	Version            string      `json:"version"`
	User               interface{} `json:"user"`
	Cpi                string      `json:"cpi"`
	StemcellOs         string      `json:"stemcell_os"`
	StemcellVersion    string      `json:"stemcell_version"`
	UserAuthentication struct {
		Type    string `json:"type"`
		Options struct {
			Url  string   `json:"url"`
			Urls []string `json:"urls"`
		} `json:"options"`
	} `json:"user_authentication"`
	Features struct {
		LocalDns struct {
			Status bool `json:"status"`
			Extras struct {
				DomainName string `json:"domain_name"`
			} `json:"extras"`
		} `json:"local_dns"`
		PowerDns struct {
			Status bool `json:"status"`
			Extras struct {
				DomainName string `json:"domain_name"`
			} `json:"extras"`
		} `json:"power_dns"`
		Snapshots struct {
			Status bool `json:"status"`
		} `json:"snapshots"`
		ConfigServer struct {
			Status bool `json:"status"`
			Extras struct {
				Urls []string `json:"urls"`
			} `json:"extras"`
		} `json:"config_server"`
	} `json:"features"`
}

type Environment struct {
	AccessToken     string       `yaml:"access_token"`
	AccessTokenType string       `yaml:"access_token_type"`
	Alias           string       `yaml:"alias"`
	CaCert          string       `yaml:"ca_cert"`
	RefreshToken    string       `yaml:"refresh_token"`
	RawDirectorURL  string       `yaml:"url"`
	DirectorURL     *url.URL     `yaml:"-"`
	UaaURL          *url.URL     `yaml:"-"`
	client          *http.Client `yaml:"-"`
}

func (e *Environment) UpdateTokens() error {
	if e.UaaURL == nil {
		err := e.init()
		if err != nil {
			return err
		}
		err = e.fetchUaaURL()
		if err != nil {
			return err
		}
	}

	err := e.refreshTokens()
	if err != nil {
		return fmt.Errorf("failed to refresh bosh access token %w", err)
	}

	return nil
}

func (e *Environment) init() error {
	var err error
	logger := zap.L()

	e.DirectorURL, err = url.Parse(e.RawDirectorURL)
	if err != nil {
		return fmt.Errorf("error parsing environment url (%v) %w", e.RawDirectorURL, err)
	}

	if e.DirectorURL.Scheme == "https" {
		logger.Info("using TLS-encrypted connection to bosh-director", zap.String("bosh-director-url", e.DirectorURL.String()))
		boshCA := x509.NewCertPool()
		ok := boshCA.AppendCertsFromPEM([]byte(e.CaCert))
		if !ok {
			return fmt.Errorf("could not add BOSH Director CA from bosh-config, adding to the cert pool failed %v", e.CaCert) //TODO really output cert here?
		}

		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig.RootCAs = boshCA

		e.client = &http.Client{
			Transport: transport,
		}
	} else {
		logger.Warn("using unencrypted connection to bosh-director", zap.String("bosh-director-url", e.DirectorURL.String()))
		e.client = http.DefaultClient
	}
	return nil
}

func (e *Environment) fetchUaaURL() error {
	res, err := e.client.Do(&http.Request{
		Method: http.MethodGet,
		URL: &url.URL{
			Scheme: e.DirectorURL.Scheme,
			Host:   e.DirectorURL.Host,
			Path:   "/info",
		},
		Header: http.Header{
			"Accept": {"application/json"},
		},
	})
	if err != nil {
		return fmt.Errorf("could not get response from bosh-director %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d from bosh-director", res.StatusCode)
	}

	defer res.Body.Close()

	var info Info
	err = json.NewDecoder(res.Body).Decode(&info)
	if err != nil {
		return err
	}

	uaaURL, err := url.Parse(info.UserAuthentication.Options.Url)
	if err != nil {
		return err
	}
	e.UaaURL = uaaURL

	return nil
}

func (e *Environment) refreshTokens() error { //TODO: logging
	req := http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: e.UaaURL.Scheme,
			Host:   e.UaaURL.Host,
			Path:   "/oauth/token",
		},
		Header: http.Header{
			"Accept":        {"application/json"},
			"Content-Type":  {"application/x-www-form-urlencoded"},
			"Authorization": {fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte("bosh_cli:")))}, // TODO: the client name is also written in the token
		},
		Body: io.NopCloser(bytes.NewReader([]byte(url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {e.RefreshToken},
		}.Encode()))),
	}
	res, err := e.client.Do(&req)
	if err != nil {
		return err
	}

	var newTokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	err = json.NewDecoder(res.Body).Decode(&newTokens)
	if err != nil {
		return err
	}

	e.RefreshToken = newTokens.RefreshToken
	e.AccessTokenType = newTokens.TokenType
	e.AccessToken = newTokens.AccessToken

	return nil
}
