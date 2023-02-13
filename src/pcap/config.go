package pcap

// TLS configures the server side of (m)TLS.
type TLS struct {
	// Certificate holds the path to the PEM encoded certificate (chain).
	Certificate string `yaml:"certificate" validate:"file"`
	// PrivateKey holds the path to the PEM encoded private key.
	PrivateKey string `yaml:"private_key" validate:"file"`
	// CertificateAuthority holds the path to the PEM encoded CA bundle which is used
	// to request and verify client certificates.
	CertificateAuthority string `yaml:"ca" validate:"file"`
}

// MutualTLS defines the client-side configuration for an mTLS connection.
//
// Certificate and PrivateKey are for the mTLS client certificate
// The CertificateAuthority is a file containing the server's CA that should be trusted when connecting to the server.
type MutualTLS struct {
	TLS
	// SkipVerify can disable the server certificate verification when connecting.
	SkipVerify bool `yaml:"skip_verify"`
	// CommonName is used as part of the certificate verification, together with CertificateAuthority.
	CommonName string `yaml:"common_name"`
}

// BufferConf allows to specify the behaviour of buffers.
//
// The recommendation is to set the upper limit slightly below the size
// to account for data put into the buffer while checking the fill condition
// or performing work. The lower limit should be low enough to make some room
// for new data but not too low (which would cause a lot of data to be
// discarded). After all the buffer should mainly soften short spikes in data
// transfer and these limits only protect against uncontrolled back pressure.
type BufferConf struct {
	// Size is the number of responses that can be buffered per stream.
	Size int `yaml:"size" validate:"gte=0"`
	// UpperLimit tells the manager of the buffer to start discarding messages
	// once the limit is exceeded. The condition looks like this:
	//   len(buf) >= UpperLimit
	UpperLimit int `yaml:"upperLimit" validate:"gte=0,ltefield=Size"`
	// LowerLimit tells the manager of the buffer to stop discarding messages
	// once the limit is reached/undercut. The condition looks like this:
	//   len(buf) <= LowerLimit
	LowerLimit int `yaml:"lowerLimit" validate:"gte=0,ltefield=UpperLimit"`
}

// Listen defines the port and optional TLS configuration for the listening socket
type Listen struct {
	Port int  `yaml:"port" validate:"gt=0,lte=65535"`
	TLS  *TLS `yaml:"tls,omitempty"`
}

// AgentMTLS defines the DefaultPort on which agents woudl listen and the optional mTLS configuration to connect to agents.
//
// The DefaultPort can be used by resolvers, when the deployed agent port is always located on the same port.
type AgentMTLS struct {
	DefaultPort int        `yaml:"port" validate:"gt=0,lte=65535"`
	MTLS        *MutualTLS `yaml:"mtls,omitempty"`
}
