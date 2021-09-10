package stun

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func TestParsePackage(t *testing.T) {
	// stander Binding-Response data copy from Wireshark
	/*
			Simple Traversal of UDP Through NAT
		    [Request In: 155]
		    [Time: 0.255326000 seconds]
		    Message Type: Binding Response (0x0101)
		    Message Length: 0x0048
		    Message Transaction ID: a2400227a6b09f5970b5f0496e30c277
		    Attributes
		        Attribute: MAPPED-ADDRESS
		            Attribute Type: MAPPED-ADDRESS (0x0001)
		            Attribute Length: 8
		            Protocol Family: IPv4 (0x0001)
		            Port: 46425
		            IP: 154.89.5.1
		        Attribute: SOURCE-ADDRESS
		        Attribute: CHANGED-ADDRESS
		        Attribute: XOR_MAPPED_ADDRESS
		        Attribute: SERVER
	*/
	data := []byte{
		0x01, 0x01, 0x00, 0x48, 0xa2, 0x40, 0x02, 0x27, 0xa6, 0xb0, 0x9f, 0x59, 0x70, 0xb5, 0xf0, 0x49,
		0x6e, 0x30, 0xc2, 0x77, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0xb5, 0x59, 0x9a, 0x59, 0x05, 0x01,
		0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x0d, 0x96, 0xd8, 0x5d, 0xf6, 0x12, 0x00, 0x05, 0x00, 0x08,
		0x00, 0x01, 0x0d, 0x97, 0xd8, 0x5d, 0xf6, 0x11, 0x80, 0x20, 0x00, 0x08, 0x00, 0x01, 0x17, 0x19,
		0x38, 0x19, 0x07, 0x26, 0x80, 0x22, 0x00, 0x14, 0x56, 0x6f, 0x76, 0x69, 0x64, 0x61, 0x2e, 0x6f,
		0x72, 0x67, 0x20, 0x30, 0x2e, 0x39, 0x38, 0x2d, 0x43, 0x50, 0x43, 0x00,
	}
	pkg, err := parsePackage(data)
	if err != nil || pkg == nil {
		t.Errorf("stander STUN repsonse package parse error:" + err.Error())
		return
	}

	mappedAddr := pkg.getMappedAddr()
	if mappedAddr == nil {
		t.Errorf("stander STUN repsonse package parse error: attribute parse error")
		return
	}

	if mappedAddr.String() != "154.89.5.1:46425" {
		t.Errorf("stander STUN repsonse package parse error: attribute data mismatch %s != %s ",
			mappedAddr.String(), "154.89.5.1:46425")
	}
}

func TestParseNoCrash(t *testing.T) {
	for i := 18; i < 1500; i++ {
		b := make([]byte, i)
		rand.Read(b)
		_, err := parsePackage(b)
		if err != nil {
			fmt.Print(err)
		}
	}
}

func TestNewPacket(t *testing.T) {
	_, err := newPacket()
	if err != nil {
		t.Errorf("newPacket error")
	}
}
