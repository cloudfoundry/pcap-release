package pcap

// ManualEndpoints defines a set of AgentEndpoints that are defined manually.
// TODO: Remove the whole file once we have resolvers for BOSH or CF.
type ManualEndpoints struct {
	Targets []AgentEndpoint
}
