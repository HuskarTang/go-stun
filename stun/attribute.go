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
**
**/
package stun

import (
	"encoding/binary"
	"net"
)

/*
   Each attribute is TLV encoded, with a 16 bit type, 16 bit length, and variable value:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Type                  |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             Value                             ....
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   The following types are defined:

   0x0001: MAPPED-ADDRESS
   0x0002: RESPONSE-ADDRESS
   0x0003: CHANGE-REQUEST
   0x0004: SOURCE-ADDRESS
   0x0005: CHANGED-ADDRESS
   0x0006: USERNAME
   0x0007: PASSWORD
   0x0008: MESSAGE-INTEGRITY
   0x0009: ERROR-CODE
   0x000a: UNKNOWN-ATTRIBUTES
   0x000b: REFLECTED-FROM
 */
type attribute struct {
	types  uint16
	length uint16
	value  []byte
}
const (
	attributeMappedAddress          = 0x0001
	attributeResponseAddress        = 0x0002
	attributeChangeRequest          = 0x0003
	attributeSourceAddress          = 0x0004
	attributeChangedAddress         = 0x0005
	attributeUsername               = 0x0006
	attributePassword               = 0x0007
	attributeMessageIntegrity       = 0x0008
	attributeErrorCode              = 0x0009
	attributeUnknownAttributes      = 0x000a
	attributeReflectedFrom          = 0x000b
)

const (
	attributeFamilyIPv4 = 0x01
	attributeFamilyIPV6 = 0x02
)

func newAttribute(types uint16, value []byte) *attribute {
	att := new(attribute)
	att.types = types
	att.value = padding(value)
	att.length = uint16(len(att.value))
	return att
}

func newChangeReqAttribute(changeIP bool, changePort bool) *attribute {
	value := make([]byte, 4)
	if changeIP {
		value[3] |= 0x04
	}
	if changePort {
		value[3] |= 0x02
	}
	return newAttribute(attributeChangeRequest, value)
}


/*       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |0 0 0 0 0 0 0 0|    Family     |           Port                |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                                                               |
 *      |                 Address (32 bits or 128 bits)                 |
 *      |                                                               |
 *	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
func (v *attribute) commAddr() *net.UDPAddr {
	addr := net.UDPAddr{}
	addr.Port = int(binary.BigEndian.Uint16(v.value[2:4]))
	addr.IP = v.value[4:v.length]
	return &addr
}
