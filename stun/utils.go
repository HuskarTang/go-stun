
package stun

import (
	"net"
)

// Padding the length of the byte slice to multiple of 4.
func padding(bytes []byte) []byte {
	length := uint16(len(bytes))
	return append(bytes, make([]byte, align(length)-length)...)
}

// Align the uint16 number to the smallest multiple of 4, which is larger than
// or equal to the uint16 number.
func align(n uint16) uint16 {
	return (n + 3) & 0xfffc
}

// isLocalAddress check if localRemote is a local address.
func isLocalAddress(local, localRemote string) bool {
	// Resolve the IP returned by the STUN server first.
	localRemoteAddr, err := net.ResolveUDPAddr("udp", localRemote)
	if err != nil {
		return false
	}
	// Try comparing with the local address on the socket first, but only if
	// it's actually specified.
	addr, err := net.ResolveUDPAddr("udp", local)
	if err == nil && addr.IP != nil && !addr.IP.IsUnspecified() {
		return addr.IP.Equal(localRemoteAddr.IP)
	}
	// Fallback to checking IPs of all interfaces
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			continue
		}
		if ip.Equal(localRemoteAddr.IP) {
			return true
		}
	}
	return false
}
