package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"net"
)

/*
   All STUN messages consist of a 20 byte header:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      STUN Message Type        |         Message Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                            Transaction ID
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                                                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   The Message Types can take on the following values:

      0x0001  :  Binding Request
      0x0101  :  Binding Response
      0x0111  :  Binding Error Response
      0x0002  :  Shared Secret Request
      0x0102  :  Shared Secret Response
      0x0112  :  Shared Secret Error Response

   The message length is the count, in bytes, of the size of the
   message, not including the 20 byte header.

   The transaction ID is a 128 bit identifier.  It also serves as salt
   to randomize the request and the response.  All responses carry the
   same identifier as the request they correspond to.
*/
type packet struct {
	types      uint16
	length     uint16
	transID    []byte // 4 serialize magic cookie + 12 serialize transaction id
	attributes []attribute
	orgHost    *net.UDPAddr
}

const (
	msgTypeBindingRequest       = 0x0001
	msgTypeBindingResponse      = 0x0101
	msgTypeBindingErrorResponse = 0x0111
	msgTypeSharedSecretRequest  = 0x0002
	msgTypeSharedSecretResponse = 0x0102
	msgTypeSharedErrorResponse  = 0x0112
)

// local defined magic Cookie
const magicCookie = 0xA2400227

func newPacket() (*packet, error) {
	v := new(packet)
	v.transID = make([]byte, 16)
	binary.BigEndian.PutUint32(v.transID[:4], magicCookie)
	_, err := rand.Read(v.transID[4:])
	if err != nil {
		return nil, err
	}
	v.attributes = make([]attribute, 0, 10)
	v.length = 0
	return v, nil
}

func parsePackage(pkgData []byte) (*packet, error) {
	if len(pkgData) < 20 {
		return nil, errors.New("received data length too short")
	}
	if len(pkgData) > math.MaxUint16 {
		return nil, errors.New("received data length too long")
	}
	pkt := new(packet)
	pkt.types = binary.BigEndian.Uint16(pkgData[0:2])
	pkt.length = binary.BigEndian.Uint16(pkgData[2:4])
	pkt.transID = pkgData[4:20]
	pkt.attributes = make([]attribute, 0, 10)
	pkgData = pkgData[20:]
	for pos := uint16(0); pos+4 < uint16(len(pkgData)); {
		types := binary.BigEndian.Uint16(pkgData[pos : pos+2])
		length := binary.BigEndian.Uint16(pkgData[pos+2 : pos+4])
		end := pos + 4 + length
		if end < pos+4 || end > uint16(len(pkgData)) {
			return nil, errors.New("received data format mismatch")
		}
		value := pkgData[pos+4 : end]
		attribute := newAttribute(types, value)
		pkt.addAttribute(*attribute)
		pos += align(length) + 4
	}

	return pkt, nil
}

func (v *packet) addAttribute(a attribute) {
	v.attributes = append(v.attributes, a)
	v.length += align(a.length) + 4
}

func (v *packet) serialize() []byte {
	packetBytes := make([]byte, 4)
	binary.BigEndian.PutUint16(packetBytes[0:2], v.types)
	binary.BigEndian.PutUint16(packetBytes[2:4], v.length)
	packetBytes = append(packetBytes, v.transID...)
	for _, a := range v.attributes {
		tmpBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(tmpBuf, a.types)
		packetBytes = append(packetBytes, tmpBuf...)
		binary.BigEndian.PutUint16(tmpBuf, a.length)
		packetBytes = append(packetBytes, tmpBuf...)
		packetBytes = append(packetBytes, a.value...)
	}
	return packetBytes
}

func (v *packet) getSourceAddr() *net.UDPAddr {
	return v.findAttrAddr(attributeSourceAddress)
}

func (v *packet) getMappedAddr() *net.UDPAddr {
	return v.findAttrAddr(attributeMappedAddress)
}

func (v *packet) getChangedAddr() *net.UDPAddr {
	return v.findAttrAddr(attributeChangedAddress)
}

func (v *packet) findAttrAddr(attribute uint16) *net.UDPAddr {
	for _, attr := range v.attributes {
		if attr.types == attribute {
			return attr.commAddr()
		}
	}
	return nil
}
