package bosh

type Config struct {
	Environments []Environment `yaml:"environments"`
}

type Environment struct {
	AccessToken     string `yaml:"access_token"`
	AccessTokenType string `yaml:"access_token_type"`
	Alias           string `yaml:"alias"`
	CaCert          string `yaml:"ca_cert"`
	RefreshToken    string `yaml:"refresh_token"`
	Url             string `yaml:"url"`
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
