package homehub

// NatRule represents a Home Hub NAT port forwarding rule
type NatRule struct {
	UID                   int    `json:"uid"`
	Enabled               bool   `json:"Enable"`
	Alias                 string `json:"Alias"`
	externalInterface     string `json:"ExternalInterface"`
	AllExternalInterfaces bool   `json:"AllExternalInterfaces"`
	LeaseDuration         int    `json:"LeaseDuration"`
	RemoteHostIP          string `json:"RemoteHost"`
	ExternalPort          int    `json:"ExternalPort"`
	ExternalPortEndRange  int    `json:"ExternalPortEndRange"`
	internalInterface     string `json:"InternalInterface"`
	InternalPort          int    `json:"InternalPort"`
	Protocol              string `json:"Protocol"`
	Service               string `json:"Service"`
	InternalClientIP      string `json:"InternalClient"`
	Description           string `json:"Description"`
	Creator               string `json:"Creator"`
	Target                string `json:"Target"`
	LeaseStart            string `json:"LeaseStart"`
}
