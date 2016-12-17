## Copyright (C) Cesar A. Bernardini <mesarpe@gmail.com>
## Intern at INRIA Grand Nancy Est
## This program is published under a GPLv2 license

## Copyright (C) Airbus Defence and Space
## Adam Reziouk, Enzo Laurent and Jonathan-Christofer Demay
## This program is published under a GPLv2 license
"""

This implementation follows the next documents:
    * RFC 4944 : Transmission of IPv6 Packets over IEEE 802.15.4 Networks
    * RFC 6282 : Compression Format for IPv6 Datagrams over IEEE 802.15.4-Based Networks

6LoWPAN Protocol Stack
======================

                            |-----------------------|
Application                 | Application Protocols |
                            |-----------------------|
Transport                   |   UDP      |   TCP    |
                            |-----------------------|
Network                     |          IPv6         | (Only IPv6)
                            |-----------------------|
                            |         LoWPAN        | (in the middle between network and data link layer)
                            |-----------------------|
Data Link Layer             |   IEEE 802.15.4 MAC   |
                            |-----------------------|
Physical                    |   IEEE 802.15.4 PHY   |
                            |-----------------------|

"""

import socket
import struct

from scapy.packet import *
from scapy.fields import *
from scapy.plist import *

from scapy.layers.inet6 import *
from scapy.layers.inet import *
from scapy.utils6 import *

from dot15d4 import Dot15d4, Dot15d4Data, Dot15d4FCS, dot15d4AddressField
from scapy.utils import *

from scapy.route6 import *

from scapy.packet import Raw

LINK_LOCAL_PREFIX = "\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

''' Default context table. User may want to edit it with the proper prefixes '''

sContext = {

        0 : struct.pack('>Q', 0),
        1 : struct.pack('>Q', 1),
        2 : struct.pack('>Q', 2),
        3 : struct.pack('>Q', 3),
        4 : struct.pack('>Q', 4),
        5 : struct.pack('>Q', 5),
        6 : struct.pack('>Q', 6),
        7 : struct.pack('>Q', 7),
        8 : struct.pack('>Q', 8),
        9 : struct.pack('>Q', 9),
        10 : struct.pack('>Q', 10),
        11 : struct.pack('>Q', 11),
        12 : struct.pack('>Q', 12),
        13 : struct.pack('>Q', 13),
        14 : struct.pack('>Q', 14),
        15 : struct.pack('>Q', 15),                
}

dContext = {

        0 : struct.pack('>Q', 0),
        1 : struct.pack('>Q', 1),
        2 : struct.pack('>Q', 2),
        3 : struct.pack('>Q', 3),
        4 : struct.pack('>Q', 4),
        5 : struct.pack('>Q', 5),
        6 : struct.pack('>Q', 6),
        7 : struct.pack('>Q', 7),
        8 : struct.pack('>Q', 8),
        9 : struct.pack('>Q', 9),
        10 : struct.pack('>Q', 10),
        11 : struct.pack('>Q', 11),
        12 : struct.pack('>Q', 12),
        13 : struct.pack('>Q', 13),
        14 : struct.pack('>Q', 14),
        15 : struct.pack('>Q', 15),                

        }


class MeshAddrfield(Field):

    __slots__ = ["length_from", "length_of"]
    
    def __init__(self, name, default, length_from=None, length_of=None,  fmt="<H"):
        Field.__init__(self, name, default, fmt)
        self.length_from=length_from
        self.length_of = length_of

    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        if len(hex(self.i2m(pkt,x))) < 7: # short address
            return hex(self.i2m(pkt,x))
        else: # long address
            #x = hex(self.i2m(pkt,x))[2:-1]
            #x = len(x) %2 != 0 and "0" + x or x
            x = hex(self.i2m(pkt,x))[2:]
            if x[-1] == "L":
                x = x[:-1]
            x = x.zfill(16)
            return ":".join(["%s%s" % (x[i], x[i+1]) for i in range(0,len(x),2)])
    def addfield(self, pkt, s, val):
        """Add an internal value to a string"""
        if self.length_from(pkt) == 2:
        #if self.length_of == 2:
            return s + struct.pack(self.fmt[0]+"H", val)
        elif self.length_from(pkt) == 8:
        #elif self.length_of == 8:
            return s + struct.pack(self.fmt[0]+"Q", val)
        else:
            return s
    def getfield(self, pkt, s):
        if self.length_from(pkt) == 2:
            return s[2:], self.m2i(pkt, struct.unpack(self.fmt[0]+"H", s[:2])[0])
        elif self.length_from(pkt) == 8:
            return s[8:], self.m2i(pkt, struct.unpack(self.fmt[0]+"Q", s[:8])[0])
        else:
            raise Exception('impossible case')
    
    

class SixLoWPANAddrField(Field):
    """Special field to store 6LoWPAN addresses

    6LoWPAN Addresses have a variable length depending on other parameters.
    This special field allows to save them, and encode/decode no matter which
    encoding parameters they have.
    """
    def __init__(self, name, default, length_of=None, fmt="<H", adjust=None):
        Field.__init__(self, name, default, fmt)
        self.length_of=length_of
        self.adjust=adjust
    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        return lhex(self.i2h(pkt,x))
    def h2i(self, pkt, x):
        """Convert human value to internal value"""
        if type(x) == int:
            return 0
        elif type(x) == str:
            return Field.h2i(self, pkt, x)
    def i2h(self, pkt, x):
        """Convert internal value to human value"""
        Field.i2h(self, pkt, x)
    def m2i(self, pkt, x):
        """Convert machine value to internal value"""
        return Field.m2i(self, pkt, x)
    def i2m(self, pkt, x):
        """Convert internal value to machine value"""
        return Field.i2m(self, pkt, x)
    def any2i(self, pkt, x):
        """Try to understand the most input values possible and make an internal value from them"""
        return self.h2i(pkt, x)
    def addfield(self, pkt, s, val):
        """Add an internal value to a string"""
        if self.length_of(pkt) == 8:
            return s + struct.pack(self.fmt[0]+"B", val)
        if self.length_of(pkt) == 16:
            return s + struct.pack(self.fmt[0]+"H", val)
        if self.length_of(pkt) == 32:
            return s + struct.pack(self.fmt[0]+"2H", val) #TODO: fix!
        if self.length_of(pkt) == 48:
            return s + struct.pack(self.fmt[0]+"3H", val) #TODO: fix!
        elif self.length_of(pkt) == 64:
            return s + struct.pack(self.fmt[0]+"Q", val)
        elif self.length_of(pkt) == 128:
            #TODO: FIX THE PACKING!!
            return s + struct.pack(self.fmt[0]+"16s", str(val))
        else:
            return s
    def getfield(self, pkt, s):
        if self.length_of(pkt) == 8:
            return s[1:], self.m2i(pkt, struct.unpack(self.fmt[0]+"B", s[:1])[0])
        elif self.length_of(pkt) == 16:
            return s[2:], self.m2i(pkt, struct.unpack(self.fmt[0]+"H", s[:2])[0])
        elif self.length_of(pkt) == 32:
            return s[4:], self.m2i(pkt, struct.unpack(self.fmt[0]+"2H", s[:2], s[2:4])[0])
        elif self.length_of(pkt) == 48:
            return s[6:], self.m2i(pkt, struct.unpack(self.fmt[0]+"3H", s[:2], s[2:4], s[4:6])[0])
        elif self.length_of(pkt) == 64:
            return s[8:], self.m2i(pkt, struct.unpack(self.fmt[0]+"Q", s[:8])[0])
        elif self.length_of(pkt) == 128:
            return s[16:], self.m2i(pkt, struct.unpack(self.fmt[0]+"16s", s[:16])[0])

class LoWPANMesh(Packet):
    name = "6LoWPAN Mesh Packet"
    fields_desc = [
        BitField("_pattern", 0x2, 2),
        BitEnumField("_v", 0x0, 1, [False, True]),
        BitEnumField("_f", 0x0, 1, [False, True]),
        BitField("_hopsLeft", 0x0, 4),
        MeshAddrfield("_sourceAddr", 0x0, length_from= lambda pkt: pkt._v and 2 or 8),
        MeshAddrfield("_destinyAddr", 0x0, length_from= lambda pkt: pkt._f and 2 or 8)
    ]

    def guess_payload_class(self, payload):

        if ord(payload[0]) >> 5 == 0x03:
            return LoWPAN_IPHC

        #if payload[0] == '\x60':
        #    return LoWPAN_IPHC

        elif payload[0] == '\x41':
            return LoWPANUncompressedIPv6

        if ord(payload[0]) >> 3 == 0x18:
            return LoWPANFragmentationFirst

        elif ord(payload[0]) >> 3 == 0x1C:
            return LoWPANFragmentationSubsequent
        
        elif payload[0] == '\x50':
            return LoWPANBroadcast
        
        else:
            return payload


class LoWPANBroadcast(Packet):
    name = "6LoWPAN Broadcast packet"
    field_desc = [
        BitField("_pattern", 0x50, 8),
        ByteField("_seqnum", 0),
        ]


    def guess_payload_class(self, payload):


        if ord(payload[0]) >> 5 == 0x03:
            return LoWPAN_IPHC

        #if payload[0] == '\x60':
        #    return LoWPAN_IPHC

        elif payload[0] == '\x41':
            return LoWPANUncompressedIPv6

        if ord(payload[0]) >> 3 == 0x18:
            return LoWPANFragmentationFirst

        elif ord(payload[0]) >> 3 == 0x1C:
            return LoWPANFragmentationSubsequent
        
        else:
            return payload
        
    
        
###############################################################################
# Fragmentation
#
# Section 5.3 - September 2007
###############################################################################

class LoWPANFragmentationFirst(Packet):
    name = "6LoWPAN First Fragmentation Packet"
    fields_desc = [
        BitField("pattern", 0x18, 5),
        BitField("datagramSize", 0x0, 11),
        XShortField("datagramTag", 0x0),
    ]
    
    def guess_payload_class(self, payload):

        if ord(payload[0]) == 0x41:
            return Raw  # Ipv6 uncompressed (fragment)

        elif ord(payload[0]) >> 5 == 0x03:
            return LoWPAN_IPHC


class LoWPANFragmentationSubsequent(Packet):
    name = "6LoWPAN Subsequent Fragmentation Packet"
    fields_desc = [
        BitField("pattern", 0x1C, 5),
        BitField("datagramSize", 0x0, 11),
        XShortField("datagramTag", 0x0), #TODO: change default value, should be a random one
        ByteField("datagramOffset", 0x0), #VALUE PRINTED IN OCTETS, wireshark does in bits (128 bits == 16 octets)
    ]

    def guess_payload_class(self, payload):
        return Raw

IPHC_DEFAULT_VERSION = 6
IPHC_DEFAULT_TF = 0
IPHC_DEFAULT_FL = 0

def source_addr_mode2(pkt):
    """source_addr_mode

    This function depending on the arguments returns the amount of bits to be
    used by the source address.

    Keyword arguments:
    pkt -- packet object instance
    """
    if pkt.sac == 0x0:
        if pkt.sam == 0x0:      return 16
        elif pkt.sam == 0x1:    return 8
        elif pkt.sam == 0x2:    return 2
        elif pkt.sam == 0x3:    return 0
    else:
        if pkt.sam == 0x0:      return 0
        elif pkt.sam == 0x1:    return 8
        elif pkt.sam == 0x2:    return 2
        elif pkt.sam == 0x3:    return 0

def destiny_addr_mode(pkt):
    """destiny_addr_mode

    This function depending on the arguments returns the amount of bits to be
    used by the destiny address.

    Keyword arguments:
    pkt -- packet object instance
    """
    if pkt.m == 0:
        if pkt.dam == 0x0:
            if pkt.dac == 0x0:
                return 16
            else:
                raise Exception('reserved')
        elif pkt.dam == 0x1:    return 8
        elif pkt.dam == 0x2:    return 2
        else:                   return 0
    elif pkt.m == 1 and pkt.dac == 0:
        if pkt.dam == 0x0:      return 16
        elif pkt.dam == 0x1:    return 6
        elif pkt.dam == 0x2:    return 4
        elif pkt.dam == 0x3:    return 1
    elif pkt.m == 1 and pkt.dac == 1:
        if pkt.dam == 0x0:      return 6
        elif pkt.dam == 0x1:    raise Exception('reserved')
        elif pkt.dam == 0x2:    raise Exception('reserved')
        elif pkt.dam == 0x3:    raise Exception('reserved')

def chr2bytes(value):
    return chr(value >> 8) + chr(value & 0x00FF)        


# LoWPAN_UDP Header Compression #
class LoWPAN_UDP(Packet):
    name = "LoWPAN UDP"
    fields_desc = [
        BitField("pattern", 0x1E, 5),
        BitEnumField("chksumformat", 0x0, 1, {0:"inline", 1:"elided"}),
        BitField("portformat", 0x0, 2),
        BitField("sport", 0x0, 16),
        BitField("dport", 0x0, 16),        
        ConditionalField(
            XShortField("chksum", 0x0),
            lambda pkt: pkt.chksumformat == 0
        )
    ]


    def guess_payload_class(self, payload):
        return Raw


    def pre_dissect(self, s):

        # Decompress UDP ports

        portformat = ord(s[0]) & 0x03;

        if portformat == 0x3:
            sport = chr2bytes(0xF0B0 + ((ord(s[1]) & 0xF0) >> 4))
            dport = chr2bytes(0xF0B0 + (ord(s[1]) & 0x0F))
            s = s[0] + sport + dport + s[2:]

        elif portformat == 0x2:
            sport = chr2bytes(0xF000 + ord(s[1])) 
            s = s[0] + sport + s[2:]

        elif portformat == 0x1:
            dport = chr2bytes(0xF000 + ord(s[2]))
            s = s[:3] + dport + s[4:]

        return s

    def post_build(self, p, pay):
        
        p += pay

        # Calcul UDP checksum

        if self.chksumformat == 0 and self.chksum == None:

            if isinstance(self.underlayer, LoWPAN_IPHC):

                ln = chr2bytes(len(pay) + 8)

                udppkt = chr2bytes(self.sport) + chr2bytes(self.dport) + ln + '\x00'*2 + pay

                self.underlayer.decompressSourceAddr()
                self.underlayer.decompressDestinyAddr()

                # Pseudo IPv6 Header
                psdhdr = socket.inet_pton(socket.AF_INET6, self.underlayer.sourceAddr) + socket.inet_pton(socket.AF_INET6, self.underlayer.destinyAddr) + '\x00'*2 + ln + '\x00'*3 + '\x11'

                ck=checksum(psdhdr+udppkt)

                p = p[0:5] + struct.pack("!H", ck) + p[7:]

            else:

                p = p[0:5] + '\x00'*2 + p[7:] 
                print "No IP underlayer to compute checksum. Leaving null."

        elif self.chksumformat == 0 and self.chksum != None:

            p = p[0:5] + struct.pack("!H", self.chksum) + p[7:]
            
        # Compress UDP ports

        if (self.sport & 0xFFF0) == 0xF0B0 and (self.sport & 0xFFF0) == 0xF0B0:
            udp_port_format = chr((ord(p[0]) & 0xFC) + 0x3)
            p = udp_port_format + chr(((self.sport & 0x000F) << 4) + (self.dport & 0x000F)) + p[5:]
        elif (self.sport & 0xFF00) == 0xF000:
            udp_port_format = chr((ord(p[0]) & 0xFC) + 0x2)
            p = udp_port_format + chr(self.sport & 0x00FF) + p[3:]
        elif (self.dport & 0xFF00) == 0xF000:
            udp_port_format = chr((ord(p[0]) & 0xFC) + 0x1)
            p = udp_port_format + p[1:3] + chr(self.dport & 0x00FF) + p[5:]
        else:
            udp_port_format = chr((ord(p[0]) & 0xFC))
            p = udp_port_format + p[1:]
        
        return p




class LoWPAN_IPHC(Packet):
    """6LoWPAN IPv6 header compressed packets

    It follows the implementation of RFC 6282.
    """
    name = "LoWPAN IP Header Compression Packet"
    fields_desc = [
        BitField("pattern", 0x03, 3),
        BitField("tf", 0x0, 2),
        BitEnumField("nh", 0x0, 1, {0:"inline", 1:"elided"}),
        BitEnumField("hlim", 0x0, 2, {0:"inline", 1:"1", 2:"64", 3:"255"}),
        BitEnumField("cid", 0x0, 1, [False, True]),
        BitEnumField("sac", 0x0, 1, [False, True]),
        BitField("sam", 0x0, 2),
        BitEnumField("m", 0x0, 1, [False, True]),
        BitEnumField("dac", 0x0, 1, [False, True]),
        BitField("dam", 0x0, 2),
        
        # Contexte Identifier Extension
        ConditionalField(
            BitField("source_context", 0x0, 4),
            lambda pkt: pkt.cid == 0x1            
        ),
        ConditionalField(
            BitField("dest_context", 0x0, 4),
            lambda pkt: pkt.cid == 0x1            
        ),

        # Traffic Class & Flow Label
        ConditionalField(
            BitField("tf_ecn", 0x0, 2),
            lambda pkt: pkt.tf != 0x3
        ),
        ConditionalField(
            BitField("tf_dscp", 0x0, 6),
            lambda pkt: pkt.tf == 0x0 or pkt.tf == 0x2
        ),
        ConditionalField(
            BitField("tf_rsv1", 0x0, 2),
            lambda pkt: pkt.tf == 0x0 or pkt.tf == 0x1         
        ),
        ConditionalField(
            BitField("tf_rsv2", 0x0, 2),
            lambda pkt: pkt.tf == 0x0           
        ),        
        ConditionalField(
            BitField("tf_flowlabel", 0x0, 20),
            lambda pkt: pkt.tf == 0x0 or pkt.tf == 0x1
        ),

        # Next Header in-line    
        ConditionalField(
            ByteEnumField("nextHeader", 59, ipv6nh),
            lambda pkt: pkt.nh == 0x0            
        ),

        # Hop Limit in-line
        ConditionalField(
            ByteField("hopLimit", 0x0),
            lambda pkt: pkt.hlim == 0x0            
        ),

        StrLenField("sourceAddr", "", length_from = source_addr_mode2),
        StrLenField("destinyAddr", "", length_from = destiny_addr_mode),
    ]

    def guess_payload_class(self, payload):

        if self.nh == 1:

            return LoWPAN_UDP

        else:

            if isinstance(self.underlayer, LoWPANFragmentationFirst):
                # Cannot dissect the remaining bytes because frame is fragmented
                return Raw

            elif self.nh == 0 and self.nextHeader == 6:

                return TCP

            elif self.nh == 0 and self.nextHeader == 17:

                return UDP

            elif self.nh == 0 and self.nextHeader == 58:

                return ICMPv6Unknown

            else:

                return payload


    def post_dissect(self, data):

        self.decompressSourceAddr()
        self.decompressDestinyAddr()

        return Packet.post_dissect(self, data)

    def do_build(self):

        self.compressSourceAddr()
        self.compressDestinyAddr()

        return Packet.do_build(self)

    
    def decompressSourceAddr(self):

        # Handling context
        if self.sac == 0:
            ''' Stateless decompression '''
            prefix_ip = LINK_LOCAL_PREFIX[0:8]

        else:
            ''' Context-based decompression'''

            if self.cid:
                prefix_ip = sContext[self.souce_context]
            else:
                # 0 is the default context id to use when sac = 1 but cid = 0
                prefix_ip = sContext[0]  


        # Handling source address mode
        if self.sam == 0x0:
            if self.sac == 0:
                tmp_ip = self.sourceAddr
            else:
                tmp_ip = struct.pack('16X')  # UNSPECIFIED ADDRESS

        elif self.sam == 0x1:

            tmp_ip = prefix_ip + self.sourceAddr

        elif self.sam == 0x2:

            tmp_ip = prefix_ip + "\x00\x00\x00\xff\xfe\x00" + self.sourceAddr

        else: # sam = 3

            ''' Address is derived from link-layer address or Mesh layer'''

            underlayer = self.underlayer

            while underlayer != None and not isinstance(underlayer, Dot15d4Data) and not isinstance(underlayer, LoWPANMesh):

                underlayer = underlayer.underlayer
            
            if isinstance(underlayer, Dot15d4Data) and isinstance(underlayer.underlayer, Dot15d4):

                if underlayer.underlayer.fcf_srcaddrmode == 3:
                    suffix_ip = struct.pack(">Q", underlayer.underlayer.src_addr)
                    suffix_ip = struct.pack("B", (struct.unpack("B", suffix_ip[0])[0] ^ 0x2)) + suffix_ip[1:8] #Turn off the bit 7.

                elif underlayer.underlayer.fcf_srcaddrmode == 2:
                    suffix_ip = "\x00\x00\x00\xff\xfe\x00" + struct.pack(">H", underlayer.underlayer.src_addr)

                else:

                    raise Exception('Wrong link-layer source address mode! Cannot decompress ipv6 src addr')
                    
                tmp_ip = prefix_ip + suffix_ip


            elif isinstance(underlayer, LoWPANMesh):

                if underlayer._v == 0:  # long
                    suffix_ip = struct.pack(">Q", underlayer._sourceAddr)
                    suffix_ip = struct.pack("B", (struct.unpack("B", suffix_ip[0])[0] ^ 0x2)) + suffix_ip[1:8] #Turn off the bit 7.

                elif underlayer._v == 1:  # short
                
                    suffix_ip = "\x00\x00\x00\xff\xfe\x00" + struct.pack(">H", underlayer._sourceAddr)

                tmp_ip = prefix_ip + suffix_ip
                
            else:
                raise Exception('Information about underlayer are needed!')

        self.sourceAddr = socket.inet_ntop(socket.AF_INET6, tmp_ip)


    def decompressDestinyAddr(self):

        ''' Mode dac = 1 and m = 1 : NOT HANDLED'''


        if self.m == 0:  # Not Multicast

            # Handling context:
            if self.dac == 0:
                ''' Stateless decompression '''
                prefix_ip = LINK_LOCAL_PREFIX[0:8]

            else:
                ''' Context-based decompression'''
                
                if self.cid:
                    prefix_ip = dContext[self.dest_context]
                else:
                    # 0 is the default context id to use when dac = 1 but cid = 0
                    prefix_ip = dContext[0]  
            
            
            # Handling destination address modes:            
            if self.dam == 0:

                if self.dac == 0:

                    tmp_ip = self.destinyAddr

                else:

                    raise Exception('Sixlowpan IPv6 Destination address Decempression: Mode dam = 0 / dac = 1 is RESERVED')

            elif self.dam ==1:

                tmp_ip = prefix_ip + self.destinyAddr

            elif self.dam == 2:

                tmp_ip = prefix_ip + "\x00\x00\x00\xff\xfe\x00" + self.destinyAddr


            else: # dam == 3

                ''' Address is derived from link-layer address'''

                underlayer = self.underlayer

                while underlayer != None and not isinstance(underlayer, Dot15d4Data) and not isinstance(underlayer, LoWPANMesh):

                    underlayer = underlayer.underlayer


                if isinstance(underlayer, Dot15d4Data) and isinstance(underlayer.underlayer, Dot15d4):

                    if underlayer.underlayer.fcf_destaddrmode == 3:
                        suffix_ip = struct.pack(">Q", underlayer.underlayer.dest_addr)
                        suffix_ip = struct.pack("B", (struct.unpack("B", suffix_ip[0])[0] ^ 0x2)) + suffix_ip[1:8] #Turn off the bit 7.

                    elif underlayer.underlayer.fcf_destaddrmode == 2:
                        suffix_ip = "\x00\x00\x00\xff\xfe\x00" + struct.pack(">H", underlayer.underlayer.dest_addr)

                    else:

                        raise Exception('Wrong link-layer source address mode! Cannot decompress ipv6 src addr')
                    
                    tmp_ip = prefix_ip + suffix_ip


                elif isinstance(underlayer, LoWPANMesh):

                    if underlayer._f == 0:  # long
                        suffix_ip = struct.pack(">Q", underlayer._destinyAddr)
                        suffix_ip = struct.pack("B", (struct.unpack("B", suffix_ip[0])[0] ^ 0x2)) + suffix_ip[1:8] #Turn off the bit 7.

                    elif underlayer._f == 1:  # short
                
                        suffix_ip = "\x00\x00\x00\xff\xfe\x00" + struct.pack(">H", underlayer._destinyAddr)

                    tmp_ip = prefix_ip + suffix_ip

                else:
                
                    raise Exception('Information about underlayer are needed!')

        else:  # Multicast 

            if self.dac == 1:  # Case M=1 and DAC = 1 not supported

                raise Exception('Mode Multicast + Context-based compression/decompresion not supoorted yet ')

            else:

                if self.dam == 0:

                    tmp_ip = self.destinyAddr

                elif self.dam == 1:

                    tmp_ip = '\xff' + self.destinyAddr[0] + struct.pack('9X') + self.destinyAddr[1:]

                elif self.dam == 2:

                    tmp_ip = '\xff' + self.destinyAddr[0] + struct.pack('11X') + self.destinyAddr[1:]

                else: # dam == 3

                    tmp_ip = "\xff\x02" + struct.pack('13X') + self.destinyAddr
                    
            
        self.destinyAddr = socket.inet_ntop(socket.AF_INET6, tmp_ip)
                



    def compressSourceAddr(self):

        ''' UNSPECIFIED ADDRESS (":") NOT HANDLED : When sac = 1 and sam = 0 '''

        if not ':' in self.sourceAddr:
            self.decompressSourceAddr()
            
        tmp_ip = socket.inet_pton(socket.AF_INET6, self.sourceAddr)

        ''' Suffixe IP depending of MAC adress '''

        underlayer = self.underlayer

        while underlayer != None and not isinstance(underlayer, Dot15d4Data) and not isinstance(underlayer, LoWPANMesh):

            underlayer = underlayer.underlayer

        # Is there a mesh packet or not ? 

        if isinstance(underlayer, Dot15d4Data) and isinstance(underlayer.underlayer, Dot15d4):
        
            if underlayer.underlayer.fcf_srcaddrmode == 3:
                suffix_ip = struct.pack(">Q", underlayer.underlayer.src_addr)
                suffix_ip = struct.pack("B", (struct.unpack("B", suffix_ip[0])[0] ^ 0x2)) + suffix_ip[1:8] #Turn off the bit 7.

            elif underlayer.underlayer.fcf_srcaddrmode == 2:
                suffix_ip = "\x00\x00\x00\xff\xfe\x00" + struct.pack(">H", underlayer.underlayer.src_addr)
                
            else:
                suffix_ip = None

        elif isinstance(underlayer, LoWPANMesh):

            if underlayer._v == 0:  # long
                suffix_ip = struct.pack(">Q", underlayer._sourceAddr)
                suffix_ip = struct.pack("B", (struct.unpack("B", suffix_ip[0])[0] ^ 0x2)) + suffix_ip[1:8] #Turn off the bit 7.

            elif underlayer._v == 1:  # short
                
                suffix_ip = "\x00\x00\x00\xff\xfe\x00" + struct.pack(">H", underlayer._sourceAddr)
                
            else:
                suffix_ip = None
            
        else:

                raise Exception('Information about underlayer are missing!')


        if tmp_ip[0:8] in sContext.values():

            ''' Context-based compression '''
            
            self.sac = 1

            for cid, prefix in sContext.iteritems():
                if prefix == tmp_ip[0:8]:
                    self.cid = 1
                    self.source_context = cid
                    prefix_ip = sContext[cid]
                    break

        else:

            ''' Stateless compression '''
            
            prefix_ip = LINK_LOCAL_PREFIX[0:8]
            self.cid = 0
            self.sac = 0
        
         
        if tmp_ip[0:8] == prefix_ip and tmp_ip[8:16] == suffix_ip:
            self.sam = 3
            tmp_ip = ""

        elif tmp_ip[0:8] == prefix_ip and tmp_ip[8:14] == "\x00\x00\x00\xff\xfe\x00":
            self.sam = 2
            tmp_ip = tmp_ip[14:16]

        elif tmp_ip[0:8] == prefix_ip:
            self.sam = 1
            tmp_ip = tmp_ip[8:16]

        else:
            self.sam = 0
            tmp_ip = tmp_ip

        self.sourceAddr = tmp_ip


    
    def compressDestinyAddr(self):

        ''' Mode dac = 1 and m = 1 : NOT HANDLED'''

        if not ':' in self.destinyAddr:
            self.decompressDestinyAddr()

        
        tmp_ip = socket.inet_pton(socket.AF_INET6, self.destinyAddr)

        # Multicast or not ?
        if tmp_ip[0] == '\xff':  # Yes

            self.dac = 0  # Case M=1 and DAC = 1 not supported
            
            self.m = 1 # multicast

            if tmp_ip[1] == '\x02' and tmp_ip[2:15] == struct.pack('13X'):

                self.dam = 3
                tmp_ip = tmp_ip[-1]

            elif tmp_ip[2:13] == struct.pack('11X'):

                self.dam = 2
                tmp_ip = tmp_ip[1] + tmp_ip[13:]

            elif tmp_ip[2:11] == struct.pack('9X'):

                self.dam = 1
                tmp_ip = tmp_ip[1] + tmp_ip[11:]

            else:

                self.dam = 0
                tmp_ip = tmp_ip
            

        else:  # No

            self.m = 0

            underlayer = self.underlayer
            
            while underlayer != None and not isinstance(underlayer, Dot15d4Data) and not isinstance(underlayer, LoWPANMesh):

                underlayer = underlayer.underlayer


            if isinstance(underlayer, Dot15d4Data) and isinstance(underlayer.underlayer, Dot15d4):

                if underlayer.underlayer.fcf_destaddrmode == 3:
                    suffix_ip = struct.pack(">Q", underlayer.underlayer.dest_addr)
                    suffix_ip = struct.pack("B", (struct.unpack("B", suffix_ip[0])[0] ^ 0x2)) + suffix_ip[1:8] #Turn off the bit 7.

                elif underlayer.underlayer.fcf_destaddrmode == 2:
                    suffix_ip = "\x00\x00\x00\xff\xfe\x00" + struct.pack(">H", underlayer.underlayer.dest_addr)
                
                else:
                    suffix_ip = None


            elif isinstance(underlayer, LoWPANMesh):

                if underlayer._f == 0:  # long
                    suffix_ip = struct.pack(">Q", underlayer._destinyAddr)
                    suffix_ip = struct.pack("B", (struct.unpack("B", suffix_ip[0])[0] ^ 0x2)) + suffix_ip[1:8] #Turn off the bit 7.

                elif underlayer._f == 1:  # short
                
                    suffix_ip = "\x00\x00\x00\xff\xfe\x00" + struct.pack(">H", underlayer._destinyAddr)
                
                else:
                    suffix_ip = None

            else:

                raise Exception('Information about underlayer are missing!')


            if tmp_ip[0:8] in dContext.values():

                ''' Context-based compression '''
            
                self.dac = 1

                for cid, prefix in dContext.iteritems():
                    if prefix == tmp_ip[0:8]:
                        self.cid = 1
                        self.dest_context = cid
                        prefix_ip = dContext[cid]
                        break

            else:

                ''' Stateless compression '''
            
                prefix_ip = LINK_LOCAL_PREFIX[0:8]


            if tmp_ip[0:8] == prefix_ip and tmp_ip[8:16] == suffix_ip:
                self.dam = 3
                tmp_ip = ""

            elif tmp_ip[0:8] == prefix_ip and tmp_ip[8:14] == "\x00\x00\x00\xff\xfe\x00":
                self.dam = 2
                tmp_ip = tmp_ip[14:16]

            elif tmp_ip[0:8] == prefix_ip:
                self.dam = 1
                tmp_ip = tmp_ip[8:16]

            else:
                self.dam = 0
                tmp_ip = tmp_ip

            

        self.destinyAddr = tmp_ip
            


class LoWPANUncompressedIPv6(Packet):

    name = "LoWPAN Uncompressed IPv6 Addresses"
    fields_desc = [
        ByteField("pattern", 0x41)
    ]

    def guess_payload_class(self, payload):
        return IPv6

class SixLoWPAN(Packet):
    name = "SixLoWPAN(Packet)"

    def guess_payload_class(self, payload):
        """Depending on the payload content, the frame type we should interpretate"""
        
        if ord(payload[0]) >> 3 == 0x18:
            return LoWPANFragmentationFirst
        elif ord(payload[0]) >> 3 == 0x1C:
            return LoWPANFragmentationSubsequent
        elif ord(payload[0]) >> 6 == 0x02:
            return LoWPANMesh
        elif ord(payload[0]) == 0x41:
            return LoWPANUncompressedIPv6
        elif ord(payload[0]) >> 5 == 0x03:
            return LoWPAN_IPHC
        else:
            return payload


# Fragment IPv6 or any other packet
MAX_SIZE = 81
MAX_PHY_SIZE = 127
MAX_SECURITY_OVERHEAD = 21
LEN_FRAG1_HEAD = 4
LEN_FRAGN_HEAD = 5

def lowpanfragment(packet, datagram_tag):
    
    """Split a packet into different links to transmit as 6LoWPAN packets."""

    if len(packet) <= MAX_PHY_SIZE :
        # Don't need to fragment
        return PacketList([packet], "Fragmented")

    ll_hdr = packet[Dot15d4FCS].copy()
    ll_hdr[Dot15d4Data].payload = NoPayload()
    ll_hdr_len = len(ll_hdr) - 2  # remove FCS

    _6lowpan_overhead_len = 0

    if LoWPANBroadcast in packet:

        _6lowpan_overhead = packet[SixLoWPAN].payload.copy()
        _6lowpan_overhead[LoWPANBroadcast].payload = NoPayload()
        _6lowpan_overhead_len = len(_6lowpan_overhead)

    elif LoWPANMesh in packet:

        _6lowpan_overhead = packet[SixLoWPAN].payload.copy()
        _6lowpan_overhead[LoWPANMesh].payload = NoPayload()
        _6lowpan_overhead_len = len(_6lowpan_overhead)

    # Datagram size is equal to the uncompressed IPv6 header length plus the plen value of the IPv6 header 
    datagram_size = 0
    uncompressed_hdr_len = 0

    _6lowpan_buf = ''
    _6lowpan_buf_len = 0

    if LoWPAN_IPHC in packet:

        uncompressed_hdr_len += 40
        datagram_size += 40 # IPv6 header before compression

        if LoWPAN_UDP in packet:

            uncompressed_hdr_len += 8 
            datagram_size += 8 # UDP header before compression
            datagram_size += len(packet[LoWPAN_UDP].payload)

            # Get sixlowpan buf
            p = packet[Dot15d4FCS].copy()
            p[LoWPAN_UDP].payload = NoPayload()
            _6lowpan_buf = str(p[LoWPAN_IPHC])
            _6lowpan_buf_len = len(_6lowpan_buf)

            # Get ipv6 payload
            ipv6_pay = str(packet[LoWPAN_UDP].payload)

            
        else:

            datagram_size += len(packet[LoWPAN_IPHC].payload)

            # Get sixlowpan headers 
            p = packet[Dot15d4FCS].copy()
            p[LoWPAN_IPHC].payload = NoPayload()
            _6lowpan_buf = str(p[LoWPAN_IPHC])
            _6lowpan_buf_len = len(_6lowpan_buf)

            # Get ipv6 payload
            ipv6_pay = str(packet[LoWPAN_IPHC].payload)

    elif IPv6 in packet:

        datagram_size = len(packet[IPv6])            

        # Get ipv6 payload
        ipv6_pay = str(packet[Ipv6])
        
    else:

        print "Malformated packet"
        return []


    def consume(p, size):
        return p[size:], p[:size]
    
    # First fragment
    payload_len = (MAX_PHY_SIZE - MAX_SECURITY_OVERHEAD - ll_hdr_len - _6lowpan_overhead_len - LEN_FRAG1_HEAD - _6lowpan_buf_len ) & 0xf8

    ipv6_pay, raw = consume(ipv6_pay, payload_len)

    if _6lowpan_overhead_len != 0:
        pkt = ll_hdr / SixLoWPAN() / _6lowpan_overhead / LoWPANFragmentationFirst(datagramTag=datagram_tag, datagramSize=datagram_size) / _6lowpan_buf / raw
    else:
        pkt = ll_hdr / SixLoWPAN() / LoWPANFragmentationFirst(datagramTag=datagram_tag, datagramSize=datagram_size) / _6lowpan_buf / raw        

    fragmented_pkts = [pkt]


    # Subsequent Fragments
    processed_ipv6_len = uncompressed_hdr_len + payload_len

    payload_len = (MAX_PHY_SIZE - MAX_SECURITY_OVERHEAD - ll_hdr_len - _6lowpan_overhead_len - LEN_FRAGN_HEAD) & 0xf8
    
    while processed_ipv6_len < datagram_size:

        if (datagram_size - processed_ipv6_len < payload_len):
            # Last fragment
            payload_len = datagram_size - processed_ipv6_len

        ipv6_pay, raw = consume(ipv6_pay, payload_len)

        if _6lowpan_overhead_len != 0:
            pkt = ll_hdr / SixLoWPAN() / _6lowpan_overhead / LoWPANFragmentationSubsequent(datagramTag=datagram_tag, datagramSize=datagram_size, datagramOffset=(processed_ipv6_len/8)) / raw
        else:
            pkt = ll_hdr / SixLoWPAN() / LoWPANFragmentationSubsequent(datagramTag=datagram_tag, datagramSize=datagram_size, datagramOffset=(processed_ipv6_len/8)) / raw        

        fragmented_pkts.append(pkt)

        processed_ipv6_len += payload_len

    return PacketList(fragmented_pkts, "Fragmented")

    




def lowpandefragment(packet_list):

    # Performing some chekings about packet_list + 
    if not len(packet_list) > 1:
        print "Cannot defragment packet! missing fragment"
        return

    if not LoWPANFragmentationFirst in packet_list[0]:
        print "Cannot defragment packet! first packet is not a LoWPANFragmentationFirst packet"
        return
        
    for p in packet_list[1:]:
        if not LoWPANFragmentationSubsequent in p:
            print "Cannot defragment packet! Packet is not a LoWPANFragmentationSubsequent packet"
            return

    datagram_size = packet_list[0].datagramSize
    datagram_tag = packet_list[0].datagramTag

    for p in packet_list[1:]:
        if p.datagramSize != datagram_size:
            print "Cannot defragment packet! Mismatching datagramSize"
            return
        if p.datagramTag != datagram_tag:
            print "Cannot defragment packet! Mismatching datagramTag"
            return
    # Performing some chekings about packet_list -

    compressed_ipv6_hdr_len = 0
    uncompressed_ipv6_len = 0
    
    if LoWPAN_IPHC in packet_list[0]:

        compressed_ipv6_hdr = packet_list[0][Dot15d4FCS].copy()

        if LoWPAN_UDP in packet_list[0]:
            compressed_ipv6_hdr[LoWPAN_UDP].payload= NoPayload()
            uncompressed_ipv6_len = 48
        else:
            compressed_ipv6_hdr[LoWPAN_IPHC].payload= NoPayload()
            uncompressed_ipv6_len = 40
            
        compressed_ipv6_hdr_len = len(compressed_ipv6_hdr[LoWPAN_IPHC])
    
    ll_hdr = packet_list[0][Dot15d4FCS].copy()
    ll_hdr[Dot15d4Data].payload = NoPayload()

    hdr = packet_list[0][SixLoWPAN].copy()
    hdr[LoWPANFragmentationFirst].underlayer.payload = NoPayload()

    data = str(packet_list[0][LoWPANFragmentationFirst].payload)

    processed_ipv6_len = len(data) - compressed_ipv6_hdr_len + uncompressed_ipv6_len
    
    for p in packet_list[1:]:
        d = str(p[LoWPANFragmentationSubsequent].payload)
        data += d
        processed_ipv6_len += len(d)

    if processed_ipv6_len != datagram_size:
        print "Cannot defragment packet! Mismatching datagram size"
        return
    
    defrag_pkt = ll_hdr / SixLoWPAN(str(hdr) + data, _underlayer=ll_hdr[Dot15d4Data])

    return defrag_pkt


bind_layers( SixLoWPAN,         LoWPANFragmentationFirst,           )
bind_layers( SixLoWPAN,         LoWPANFragmentationSubsequent,      )
bind_layers( SixLoWPAN,         LoWPANMesh,                         )
bind_layers( SixLoWPAN,         LoWPAN_IPHC,                        )
bind_layers( SixLoWPAN,         LoWPANUncompressedIPv6,             )
bind_layers( LoWPANMesh,        LoWPANFragmentationFirst,           )
bind_layers( LoWPANMesh,        LoWPANFragmentationSubsequent,      )
bind_layers( LoWPANMesh,        LoWPANBroadcast                     ) 
bind_layers( LoWPANFragmentationFirst, LoWPAN_IPHC,                 )
bind_layers( LoWPANFragmentationSubsequent, LoWPAN_IPHC             )
bind_layers( Dot15d4Data,       SixLoWPAN,                          )

