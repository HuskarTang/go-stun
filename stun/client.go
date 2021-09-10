/*
** Copyright 2021 huskerTang <huskertang@gmail.com>
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**      http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
**/
package stun

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"
)

type Client struct {
	nLocalAddr   *net.UDPAddr
	nSrvAddr     *net.UDPAddr
	nChangedAddr *net.UDPAddr
	nMappedAddr  *net.UDPAddr
	conn         net.PacketConn
}

const (
	maxRetransmitNum        = 9
	defRetransmitIntervalMs = 100
	maxTimeoutMs            = 1600
	maxPacketSize           = 1024
)

// callback function in testing, to check current response package is or not a expect package
type chkfun func(cli *Client, pkg *packet) bool

func buildBindingRequest(changeIP bool, changePort bool) *packet {
	pkt, err := newPacket()
	if err != nil {
		return nil
	}
	pkt.types = msgTypeBindingRequest
	if changeIP || changePort {
		attribute := newChangeReqAttribute(changeIP, changePort)
		pkt.addAttribute(*attribute)
	}
	return pkt
}

// RFC 3489: Clients SHOULD retransmit the request starting with an interval
// of 100ms, doubling every retransmit until the interval reaches 1.6s.
// Retransmissions continue with intervals of 1.6s until a response is
// received, or a total of 9 requests have been sent.
func (c *Client) fsmSendPackageWaitReply(rqst *packet, srvAddr net.Addr, fchk chkfun) (*packet, error) {
	rqstPkgData := rqst.serialize()
	conn := c.conn
	timeout := defRetransmitIntervalMs
	rcvPkgData := make([]byte, maxPacketSize)
	for i := 0; i < maxRetransmitNum; i++ {
		// Send packet to the server.
		length, err := conn.WriteTo(rqstPkgData, srvAddr)
		if err != nil {
			return nil, err
		}
		if length != len(rqstPkgData) {
			return nil, errors.New("error in sending rqstPkgData")
		}
		err = conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))
		if err != nil {
			return nil, err
		}
		if timeout < maxTimeoutMs {
			timeout *= 2
		}

		for {
			length, peerAddr, err := conn.ReadFrom(rcvPkgData)
			if err != nil {
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					break
				}
				return nil, err
			}
			p, err := parsePackage(rcvPkgData[0:length])
			if err != nil {
				return nil, err
			}

			// If transId mismatches, keep reading until get a
			// matched packet or timeout.
			if !bytes.Equal(rqst.transID, p.transID) {
				continue
			}
			p.orgHost = peerAddr.(*net.UDPAddr)
			if !fchk(c, p) {
				// this package not match this testing
				continue
			}
			return p, nil
		}
	}
	return nil, nil
}

// Follow RFC 3489
//                        +--------+
//                        |  Test  |
//                        |   I    |
//                        +--------+
//                             |
//                             |
//                             V
//                            /\              /\
//                         N /  \ Y          /  \ Y             +--------+
//          UDP     <-------/Resp\--------->/ IP \------------->|  Test  |
//          Blocked         \ ?  /          \Same/              |   II   |
//                           \  /            \? /               +--------+
//                            \/              \/                    |
//                                             | N                  |
//                                             |                    V
//                                             V                    /\
//                                         +--------+  Sym.      N /  \
//                                         |  Test  |  UDP    <---/Resp\
//                                         |   II   |  Firewall   \ ?  /
//                                         +--------+              \  /
//                                             |                    \/
//                                             V                     |Y
//                  /\                         /\                    |
//   Symmetric  N  /  \       +--------+   N  /  \                   V
//      NAT  <--- / IP \<-----|  Test  |<--- /Resp\               Open
//                \Same/      |  III   |     \ ?  /               Internet
//                 \? /       +--------+      \  /
//                  \/                         \/
//                  |Y                          |Y
//                  |                           |
//                  |                           V
//                  |                           Full
//                  |                           Cone
//                  V              /\
//              +--------+        /  \ Y
//              |  Test  |------>/Resp\---->Restricted
//              |   IV   |       \ ?  /
//              +--------+        \  /
//                                 \/
//                                  |N
//                                  |       Port
//                                  +------>Restricted

/*
 * send a pure Binding-Request to SERVER I
 * wait for a response with MAPPED-ADDRESS and CHANGED-ADDRESS
 */
func (c *Client) doTest1(srvAddr net.Addr) (NATType, error) {
	pkg := buildBindingRequest(false, false)

	fchk := func(cli *Client, pkg *packet) bool {
		mappedAddr := pkg.getMappedAddr()
		changedAddr := pkg.getChangedAddr()
		if mappedAddr == nil || changedAddr == nil {
			fmt.Println("test1 recv package, but check FAILED...")
			return false
		}
		fmt.Println("test1 recv package and check OK")
		return true
	}

	reply, err := c.fsmSendPackageWaitReply(pkg, srvAddr, fchk)
	if err != nil {
		return NATTypeError, err
	}
	if reply == nil {
		return NATTypeUdpBlocked, nil
	}
	c.nMappedAddr = reply.getMappedAddr()
	c.nChangedAddr = reply.getChangedAddr()
	return NATTypeUnknown, nil // tobe continue
}

/*
 * send a Binding-Request with Change-IP and Change-Port marked
 * wait for response from SERVER II (Changed-IP)
 */
func (c *Client) doTest2(srvAddr net.Addr) (NATType, error) {
	pkg := buildBindingRequest(true, true)

	fchk := func(cli *Client, pkg *packet) bool {
		if cli.nChangedAddr.String() == pkg.orgHost.String() {
			fmt.Println("test2 recv package and check OK")
			return true
		}
		fmt.Println("test2 recv package, but check FAILED...")
		return false
	}

	reply, err := c.fsmSendPackageWaitReply(pkg, srvAddr, fchk)
	if err != nil {
		return NATTypeError, err
	}

	hasPublicIP := c.nMappedAddr.String() == c.nLocalAddr.String()
	if reply == nil {
		// test1 show a MAPPED-ADDRESS same as LOCAL-ADDRESS, but can NOT receive packages from SERVER II
		// So the station be behind a UDP Symmetric Firewall
		if hasPublicIP {
			return NATTypeSymmetricUDPFirewall, nil
		}
		return NATTypeUnknown, nil // tobe continue
	}

	if hasPublicIP {
		// test1 show a MAPPED-ADDRESS same as LOCAL-ADDRESS, and receive packages from SERVER II
		// So the station is on a Open Internet network
		return NATTypeOpenInternet, nil
	} else {
		// the station can receive packages from SERVER II, passed by the same mapped connection
		// so the station is on a Full Cone NAT network
		return NATTypeFullCone, nil
	}
}

/*
 *  send a pure Binding-Request to SERVER II
 *  wait for a response from SERVER II, with MAPPED-ADDRESS
 */
func (c *Client) doTest3(srvAddr net.Addr) (NATType, error) {
	pkg := buildBindingRequest(false, false)

	fchk := func(cli *Client, pkg *packet) bool {
		mappedAddr := pkg.getMappedAddr()
		if mappedAddr == nil {
			fmt.Println("test3 recv package, but check FAILED...")
			return false
		}
		fmt.Println("test3 recv package and check OK")
		return true
	}

	reply, err := c.fsmSendPackageWaitReply(pkg, srvAddr, fchk)
	if err != nil {
		return NATTypeError, err
	}
	if reply == nil {
		return NATTypeError, errors.New("the CHANGED server had NO answer")
	}
	nmapAddr := reply.getMappedAddr()
	if nmapAddr.String() != c.nMappedAddr.String() {
		// the station connected to different SERVERS and got different MAPPED-ADDRESS
		// so the station is on a Symmetric NAT network
		return NATTypeSymmetric, nil
	}
	return NATTypeUnknown, nil // tobe continue
}

/*
 * send a Binding-Request to SERVER I, with Change-Port marked
 * wait for a response from SERVER I, and it's Source-Port different from the required port
 */
func (c *Client) doTest4(srvAddr net.Addr) (NATType, error) {
	// change port
	pkg := buildBindingRequest(false, true)

	fchk := func(cli *Client, pkg *packet) bool {
		srvUdpAddr := srvAddr.(*net.UDPAddr)
		if pkg.orgHost.Port != srvUdpAddr.Port {
			fmt.Println("test4 recv package and check OK")
			return true
		}
		fmt.Println("test4 recv package, but check FAILED...")
		return false
	}

	reply, err := c.fsmSendPackageWaitReply(pkg, srvAddr, fchk)
	if err != nil {
		return NATTypeError, err
	}
	if reply == nil {
		return NATTypePortRestricted, nil
	}
	// the station can receive packages from server, with different Source-Port
	// so the station is on a Address Restricted Cone NAT network
	return NATTypeRestricted, nil
}

func (c *Client) doDetect() (nattyp NATType, err error) {
	nattyp, err = c.doTest1(c.nSrvAddr)
	if err != nil || nattyp != NATTypeUnknown {
		return nattyp, err
	}

	nattyp, err = c.doTest2(c.nSrvAddr)
	if err != nil || nattyp != NATTypeUnknown {
		return nattyp, err
	}

	nattyp, err = c.doTest3(c.nChangedAddr)
	if err != nil || nattyp != NATTypeUnknown {
		return nattyp, err
	}
	return c.doTest4(c.nSrvAddr)
}

func NewClient() *Client {
	c := new(Client)
	return c
}

func (c *Client) Discovery(srvAddrStr string) (NATType, error) {
	if srvAddrStr == "" {
		srvAddrStr = DefaultServerAddr
	}

	// 1, select local address
	serverUDPAddr, err := net.ResolveUDPAddr("udp", srvAddrStr)
	if err != nil {
		return NATTypeError, err
	}
	if serverUDPAddr == nil {
		return NATTypeError, errors.New("cat resolve STUN server:" + srvAddrStr)
	}
	conn, err := net.DialUDP("udp", nil, serverUDPAddr)
	if err != nil {
		return NATTypeError, errors.New("fail to connect to STUN server:" + srvAddrStr)
	}
	pkg := buildBindingRequest(false, false)
	if pkg == nil {
		return NATTypeError, errors.New("runtime error")
	}
	_, _ = conn.Write(pkg.serialize())
	lcUdpAddr := conn.LocalAddr()
	if lcUdpAddr == nil {
		return NATTypeError, errors.New("runtime error")
	}
	c.nLocalAddr = lcUdpAddr.(*net.UDPAddr)
	c.nSrvAddr = serverUDPAddr

	_ = conn.Close()

	// 2, setup local UDP listen socket
	conn, err = net.ListenUDP("udp", c.nLocalAddr)
	if err != nil {
		return NATTypeError, err
	}
	defer conn.Close()
	c.conn = conn

	//3, do detect
	return c.doDetect()
}
