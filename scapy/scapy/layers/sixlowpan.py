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



class MeshAddrfield(Field):

    def __init__(self, name, default, length_from=None, fmt="<H"):
        Field.__init__(self, name, default, fmt)
        self.length_from=length_from

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
        if self.length_of == 2:
            return s + struct.pack(self.fmt[0]+"H", val)
        elif self.length_of == 8:
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


#        ConditionalField(
#            SixLoWPANAddrField("_sourceAddr", 0x0, length_of=lambda pkt: pkt.__v and 2 or 8),
#            lambda pkt: source_addr_mode2(pkt) != 0
#        ),
#        ConditionalField(
#            SixLoWPANAddrField("_destinyAddr", 0x0, length_of=lambda pkt: pkt.__f and 2 or 8),
#            lambda pkt: destiny_addr_mode(pkt) != 0
#        ),
    ]

    def guess_payload_class(self, payload):
        # check first 2 bytes if they are ZERO it's not a 6LoWPAN packet
        pass
        
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

        if self.chksumformat == 0:

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

        if self.sourceAddr != None or self.sourceAddr != "":
            tmp_ip = self.sourceAddr
        else:
            tmp_ip = "\x00"*16
            
        if self.sac == 0:
            prefix_ip = LINK_LOCAL_PREFIX[0:8]
        else:
            prefix_ip = "\x00\x00\x00\x00\x00\x00\x00\x00"

        if self.sam == 0x0:
            if self.sac == 0:
                pass
            else:
                tmp_ip = ""
        elif self.sam == 0x1:
            tmp_ip = prefix_ip + tmp_ip[-8:]
        elif self.sam == 0x2:
            tmp_ip = prefix_ip + "\x00\x00\x00\xff\xfe\x00" + tmp_ip[-2:]
        else: # self.sam == 0x3 EXTRACT ADDRESS FROM Dot15d4
            underlayer = self.underlayer
            while underlayer != None and type(underlayer) != SixLoWPAN:
                underlayer = underlayer.underlayer
            underlayer = underlayer.underlayer

            if type(underlayer) == Dot15d4AuxSecurityHeader2003 or type(underlayer) == Dot15d4AuxSecurityHeader:
                underlayer = underlayer.underlayer
            
            if type(underlayer) == Dot15d4Data:
                if underlayer.underlayer.fcf_srcaddrmode == 3:
                    tmp_ip = prefix_ip + struct.pack(">Q", underlayer.src_addr)
                    #Turn off the bit 7.
                    tmp_ip = tmp_ip[0:8] + struct.pack("B", (struct.unpack("B", tmp_ip[8])[0] ^ 0x2)) + tmp_ip[9:16]
                elif underlayer.underlayer.fcf_srcaddrmode == 2:
                    tmp_ip = prefix_ip + "\x00\x00\x00\xff\xfe\x00" + struct.pack(">Q", underlayer.src_addr)
            else:
                #payload = packet.payload
                #Most of the times, it's necessary the IEEE 802.15.4 data to extract this address
                raise Exception('Unimplemented: IP Header is contained into IEEE 802.15.4 frame, in this case it\'s not available.')
        
        self.sourceAddr = socket.inet_ntop(socket.AF_INET6, tmp_ip)

    def decompressDestinyAddr(self):

        if self.destinyAddr != None or self.destinyAddr != "":
            tmp_ip = self.destinyAddr
        else:
            tmp_ip = "\x00"*16

        if self.m == 0:
            if self.dac == 0:
                prefix_ip = LINK_LOCAL_PREFIX[0:8]
            else:
                prefix_ip = "\x00\x00\x00\x00\x00\x00\x00\x00"

            if self.dam == 0:
                if self.dac == 0:
                    pass
                else:
                    raise Exception('Reserved')

            elif self.dam == 1:
                tmp_ip = prefix_ip + tmp_ip[-8:]
            elif self.dam == 2:
                tmp_ip = prefix_ip + "\x00\x00\x00\xff\xfe\x00" + tmp_ip[-2:]
            else: # dam = 3
                underlayer = self.underlayer
                while underlayer != None and type(underlayer) != SixLoWPAN:
                    underlayer = underlayer.underlayer
                underlayer = underlayer.underlayer

                if type(underlayer) == Dot15d4AuxSecurityHeader2003 or type(underlayer) == Dot15d4AuxSecurityHeader:
                    underlayer = underlayer.underlayer

                if type(underlayer) == Dot15d4Data:
                    if underlayer.underlayer.fcf_destaddrmode == 3:
                        tmp_ip = prefix_ip + struct.pack(">Q", underlayer.dest_addr)
                        #Turn off the bit 7.
                        tmp_ip = tmp_ip[0:8] + struct.pack("B", (struct.unpack("B", tmp_ip[8])[0] ^ 0x2)) + tmp_ip[9:16]
                    elif underlayer.underlayer.fcf_destaddrmode == 2:
                        tmp_ip = prefix_ip + "\x00\x00\x00\xff\xfe\x00" + struct.pack(">Q", underlayer.dest_addr)
                else:
                    #payload = packet.payload
                    #Most of the times, it's necessary the IEEE 802.15.4 data to extract this address
                    raise Exception('Unimplemented: IP Header is contained into IEEE 802.15.4 frame, in this case it\'s not available.')

        elif self.m == 1 and self.dac == 0:
            if self.dam == 0:
                tmp_ip=tmp_ip
            elif self.dam == 1:
                tmp_ip = "\xff" + tmp_ip[0] + "\x00"*9 + tmp_ip[-5:]
            elif self.dam == 2:
                tmp_ip = "\xff" + tmp_ip[0] + "\x00"*11 + tmp_ip[-3:]
            else: # self.dam == 3:
                tmp_ip = "\xff\x02" + "\x00"*13 + tmp_ip[-1:]
        elif self.m == 1 and self.dac == 1:
            if self.dam == 0x0:
                tmp_ip = "\xff" + tmp_ip[0:2] + "\x88" + chr(self.dest_context*16 + self.dest_context)*8 + tmp_ip[2:6]
            else: #all the others values
                raise Exception("Reserved")
                   
        self.destinyAddr = socket.inet_ntop(socket.AF_INET6, tmp_ip)
    
    def compressSourceAddr(self):

        if not ':' in self.sourceAddr or self.sourceAddr == "":
            self.decompressSourceAddr()
        
        tmp_ip = socket.inet_pton(socket.AF_INET6, self.sourceAddr)

        # Prefixe IP depending of context-based compression or not
        if self.sac == 0:
            prefix_ip = LINK_LOCAL_PREFIX[0:8]
        else:
            prefix_ip = "\x00"*8       

        # Suffixe IP depending of MAC adress
        underlayer = self.underlayer
        if underlayer != None:            
            while underlayer != None and type(underlayer) != SixLoWPAN:
                underlayer = underlayer.underlayer
            underlayer = underlayer.underlayer
            if type(underlayer) == Dot15d4AuxSecurityHeader2003 or type(underlayer) == Dot15d4AuxSecurityHeader:
                underlayer = underlayer.underlayer
            assert type(underlayer) == Dot15d4Data
            if underlayer.underlayer.fcf_srcaddrmode == 3:
                suffix_ip = struct.pack(">Q", underlayer.src_addr)
                #Turn off the bit 7.
                suffix_ip = struct.pack("B", (struct.unpack("B", suffix_ip[0])[0] ^ 0x2)) + suffix_ip[1:8]
            elif underlayer.underlayer.fcf_srcaddrmode == 2:
                suffix_ip = "\x00\x00\x00\xff\xfe\x00" + struct.pack(">Q", underlayer.src_addr)
            
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
            if self.sac == 0:
                tmp_ip = tmp_ip
            else:
                tmp_ip = ""

        self.sourceAddr = tmp_ip
    
    def compressDestinyAddr(self):

        if not ':' in self.destinyAddr or self.destinyAddr == "":
            self.decompressDestinyAddr()
        
        tmp_ip = socket.inet_pton(socket.AF_INET6, self.destinyAddr)

        # Prefixe IP depending of context-based compression or not
        if self.dac == 0:
            prefix_ip = LINK_LOCAL_PREFIX[0:8]
        else:
            prefix_ip = "\x00"*8       

        # Suffixe IP depending of MAC adress
        underlayer = self.underlayer
        if underlayer != None:
            while underlayer != None and type(underlayer) != SixLoWPAN:
                underlayer = underlayer.underlayer
            underlayer = underlayer.underlayer
            if type(underlayer) == Dot15d4AuxSecurityHeader2003 or type(underlayer) == Dot15d4AuxSecurityHeader:
                underlayer = underlayer.underlayer
            assert type(underlayer) == Dot15d4Data
            if underlayer.underlayer.fcf_destaddrmode == 3:
                suffix_ip = struct.pack(">Q", underlayer.dest_addr)
                #Turn off the bit 7.
                suffix_ip = struct.pack("B", (struct.unpack("B", suffix_ip[0])[0] ^ 0x2)) + suffix_ip[1:8]
            elif underlayer.underlayer.fcf_destaddrmode == 2:
                suffix_ip = "\x00\x00\x00\xff\xfe\x00" + struct.pack(">Q", underlayer.dest_addr)

        # Multicast address
        if tmp_ip[0] == "\xff":
            
            self.m = 1

            if self.dac == 0:
                if tmp_ip[0:15] == ("\xff\x02" + "\x00"*13):
                    self.dam = 3                    
                    tmp_ip = tmp_ip[15:16]
                elif tmp_ip[0] == "\xff" and tmp_ip[2:13] == "\x00"*11:
                    self.dam = 2                    
                    tmp_ip = tmp_ip[1] + tmp_ip[13:16]
                elif tmp_ip[0] == "\xff" and tmp_ip[2:11] == "\x00"*9:
                    self.dam = 1                    
                    tmp_ip = tmp_ip[1] + tmp_ip[11:16]
                else:
                    self.dam = 0                    
                    tmp_ip = tmp_ip
            else:
                if self.cid == 1:
                    rad_ip = chr(self.dest_context*16 + self.dest_context)*8
                else:
                    rad_ip = "\x00" * 8

                if tmp_ip[3] == "\x88" and tmp_ip[4:12] == rad_ip:
                    self.dam = 0
                    tmp_ip = tmp_ip[1:3] + tmp_ip[12:16]
                else:
                    raise Exception('Reserved')
        # Not multicast address           
        else:

            self.m = 0

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

                if self.dac == 0:
                    tmp_ip = tmp_ip
                else:
                    raise Exception('Reserved')

        
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




'''
def lowpanfragment(packet, datagram_tag):
    
    if Dot15d4FCS in packet and Dot15d4Data in packet:
        
            ll_pkt = packet[Dot15d4FCS].copy()
            

            
            

            ll_len = 
'''       

# Fragment IPv6 or any other packet
MAX_SIZE = 80


'''
 plist = self.lowpanfragment(pkt, self.hdr6_len, self.uncomp_hdr_len, datagram_size, self.datagram_tag)
'''


def lowpanfragment(packet, hdr6_len, uncomp_hdr_len, datagram_size, datagram_tag):

    """Split a packet into different links to transmit as 6LoWPAN packets."""

    # Datagram size is equal to the uncompressed IPv6 header length plus the plen value of the IPv6 header 

    if packet[Dot15d4FCS] != None and packet[Dot15d4Data] != None:

        dot15d4 = packet[Dot15d4FCS].copy()

        if Dot15d4AuxSecurityHeader2003 in dot15d4:
            dot15d4[Dot15d4AuxSecurityHeader2003].payload = None

        elif Dot15d4AuxSecurityHeader in dot15d4:
            dot15d4[Dot15d4AuxSecurityHeader].payload = None

        else:
            dot15d4[Dot15d4Data].payload = None

        #dot15d4[Dot15d4Data].payload = None  avant modif
        #lendot15d4 = len(str(dot15d4)) - 2  avant modif

        lendot15d4 = len(str(dot15d4)) - 2

    else:
        dot15d4 = None
        lendot15d4 = 0

    
    str_packet = str(packet)[lendot15d4:]

    if len(str_packet) <= MAX_SIZE:
        return PacketList([packet], "Fragmented")


    def consume(p, size):
        return p[size:], p[:size]


    payload_len = (MAX_SIZE - hdr6_len - 4) & 0xf8  # 4 is the length of the FRAG1 HEADER

    str_packet, pkt = consume(str_packet, hdr6_len + payload_len)

    pkt = dot15d4 / LoWPANFragmentationFirst(datagramTag=datagram_tag, datagramSize=datagram_size) / Raw(pkt)

    fragmented_pkts = [pkt]
    
    processed_ipv6_len = uncomp_hdr_len + payload_len
    
    while processed_ipv6_len < datagram_size:
        
        payload_len = (MAX_SIZE - 5) & 0xf8  # 5 is the length of the FRAGN HEADER

        if ( datagram_size - processed_ipv6_len < payload_len):
            # Last fragment
            payload_len = datagram_size - processed_ipv6_len

        str_packet, pkt = consume(str_packet, payload_len)

        pkt = dot15d4 / LoWPANFragmentationSubsequent(datagramTag=datagram_tag, datagramSize=datagram_size, datagramOffset=(processed_ipv6_len>>3)) / Raw(pkt)

        fragmented_pkts.append(pkt)

        processed_ipv6_len += payload_len

    return PacketList(fragmented_pkts, "Fragmented")

    




def lowpandefragment(packet_list):


    if packet_list[0][LoWPANFragmentationFirst] != None:

        datagram_tag = packet_list[0][LoWPANFragmentationFirst].datagramTag
        datagram_size = packet_list[0][LoWPANFragmentationFirst].datagramSize
        #datagram_offset = len(packet_list[0][LoWPANFragmentationFirst].payload)

        if packet_list[0][Dot15d4FCS] != None and packet_list[0][Dot15d4Data] != None:
            dot15d4 = packet_list[0][Dot15d4FCS].copy()

            if Dot15d4AuxSecurityHeader2003 in dot15d4:
                dot15d4[Dot15d4AuxSecurityHeader2003].payload = None

            elif Dot15d4AuxSecurityHeader in dot15d4:
                dot15d4[Dot15d4AuxSecurityHeader].payload = None

            else:
                dot15d4[Dot15d4Data].payload = None

            dot15d4 = str(dot15d4)[:-2]  # Remove FCS

        else:
            dot15d4 = None

        payload = str(packet_list[0][LoWPANFragmentationFirst].payload)

        for p in packet_list[1:]:

            if p[LoWPANFragmentationSubsequent] != None and p[LoWPANFragmentationSubsequent].datagramTag == datagram_tag:
                payload += str(p[LoWPANFragmentationSubsequent].payload)
            else:
                print "Packet ignored"
                return None

        if (packet_list[-1].datagramOffset*8 + len(packet_list[-1][LoWPANFragmentationSubsequent].payload)) == datagram_size:
            return Dot15d4FCS(dot15d4 + payload)
        else:
            print "Error: The packet is not full"
    else:
        print "Error: The first packet is not a First fragment packet"

    return None

bind_layers( SixLoWPAN,         LoWPANFragmentationFirst,           )
bind_layers( SixLoWPAN,         LoWPANFragmentationSubsequent,      )
bind_layers( SixLoWPAN,         LoWPANMesh,                         )
bind_layers( SixLoWPAN,         LoWPAN_IPHC,                        )
bind_layers( SixLoWPAN,         LoWPANUncompressedIPv6,             )
bind_layers( LoWPANMesh,        LoWPANFragmentationFirst,           )
bind_layers( LoWPANMesh,        LoWPANFragmentationSubsequent,      )
bind_layers( LoWPANFragmentationFirst, LoWPAN_IPHC,                 )
bind_layers( LoWPANFragmentationSubsequent, LoWPAN_IPHC             )
bind_layers( Dot15d4Data,       SixLoWPAN,                          )
 
