package api

type Handlers struct {
	Bosh bool `json:"bosh"`
	Cf   bool `json:"cf"`
}

type Status struct {
	Up       bool     `json:"Up"`
	Handlers Handlers `json:"handlers"`
}
