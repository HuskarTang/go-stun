package stun

const (
	DefaultServerAddr   = "stun.ekiga.net:3478"
)

// NATType is the type of NAT described by int.
type NATType int

// NAT types.
const (
	NATTypeUnknown NATType = iota
	NATTypeOpenInternet
	NATTypeFullCone
	NATTypeRestricted
	NATTypePortRestricted
	NATTypeSymmetricUDPFirewall
	NATTypeSymmetric
	NATTypeUdpBlocked
	NATTypeError
)

var natTypeDescription = map[NATType]string{
	NATTypeUnknown:              "NAT type indeterminacy",
	NATTypeOpenInternet:         "Open internet",
	NATTypeFullCone:             "Full cone NAT",
	NATTypeRestricted:           "Restricted NAT",
	NATTypePortRestricted:       "Port restricted NAT",
	NATTypeSymmetric:            "Symmetric NAT",
	NATTypeSymmetricUDPFirewall: "Symmetric UDP firewall",
	NATTypeUdpBlocked:           "UDP blocked firewall",
	NATTypeError:                "Detecting failed",
}

func (nat NATType) String() string {
	if s, ok := natTypeDescription[nat]; ok {
		return s
	}
	return "Unknown"
}





