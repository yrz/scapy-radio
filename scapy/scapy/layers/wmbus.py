# -*- coding: utf-8 -*-
## This file is for use with Scapy
## See http://www.secdev.org/projects/scapy for more information
## Copyright (C) Airbus Defence and Space
## Authors: Jean-Michel Huguet, Adam Reziouk, Jonathan-Christofer Demay
## This program is published under a GPLv2 license


"""
Wireless M-Bus.

Table : Channel vs Frame Type


 CHANNEL |          DESC.      ||  Ver=0 (FRAME A)  |  Ver=1 (FRAME B)  |
-------------------------------------------------------------------------
S1       |  Simplex            ||     Channel=0     |     Channel=0     |
-------------------------------------------------------------------------
S2       |  Duplex             ||     Channel=0     |        NA         |
-------------------------------------------------------------------------
C1       |  Simplex            ||     Channel=2     |     Channel=2     |
-------------------------------------------------------------------------
T1       |  Simplex            ||     Channel=1     |        NA         |
-------------------------------------------------------------------------
T2M      |  Duplex from Meter  ||     Channel=2     |     Channel=2     |
-------------------------------------------------------------------------
T2C      |  Duplex to Meter    ||     Channel=1     |        NA         |
-------------------------------------------------------------------------
C2M      |  Duplex from Meter  ||     Channel=2     |     Channel=2     |
-------------------------------------------------------------------------
C2C      |  Duplex to Meter    ||     Channel=3     |     Channel=3     |
-------------------------------------------------------------------------



encrypted pkt :
a=WMBusLinkA("\x1e\x44\xc4\x18\x64\x16\x10\x23\x01\x02\x1b\xd6\x7a\x27\x00\x10\x85\x57\x00\x05\xa6\xc1\x31\xb9\x7b\x26\x68\xc3\xFF\xFF\xcf\x29\x0d\x3b\x7a\xDF\x8F")

address =>  str(a)[2:10]
key     =>  "\x12\x34\x56\x78\x91\x23\x45\x67\x89\x12\x34\x56\x78\x9A\xBC\xDE"
iv      =>  "\xC4\x18\x64\x16\x10\x23\x01\x02\x27\x27\x27\x27\x27\x27\x27\x27"



cleartext ELL pkt :
b=WMBusLinkB("\x10\x44\x2D\x2C\x45\x45\x71\x63\x1B\x16\x8D\x20\x6A\x11\xFB\x7C\x25\x04\x05\xfd\x85\x0a\x00\x02\xfd\x08\x0b\x16")


"""


import struct
import datetime

from scapy.packet import *
from scapy.fields import *
from scapy.layers.mbus import * #Import MBus Application layer
from scapy.layers.mbus_enums import *

try:
    from scapy.crypto.CryptoWMBus import * #Import crypto
except ImportError:
    log_loading.info("Can't import CryptoWMBus. Won't be able to decrypt frames.")



crcTable =[ 0x0000, 0x3D65, 0x7ACA, 0x47AF, 0xF594, 0xC8F1, 0x8F5E, 0xB23B, 0xD64D, 0xEB28, 0xAC87, 0x91E2, 0x23D9, 0x1EBC, 0x5913, 0x6476, 0x91FF, 0xAC9A, 0xEB35, 0xD650, 0x646B, 0x590E, 0x1EA1, 0x23C4, 0x47B2, 0x7AD7, 0x3D78, 0x001D, 0xB226, 0x8F43, 0xC8EC, 0xF589, 0x1E9B, 0x23FE, 0x6451, 0x5934, 0xEB0F, 0xD66A, 0x91C5, 0xACA0, 0xC8D6, 0xF5B3, 0xB21C, 0x8F79, 0x3D42, 0x0027, 0x4788, 0x7AED, 0x8F64, 0xB201, 0xF5AE, 0xC8CB, 0x7AF0, 0x4795, 0x003A, 0x3D5F, 0x5929, 0x644C, 0x23E3, 0x1E86, 0xACBD, 0x91D8, 0xD677, 0xEB12, 0x3D36, 0x0053, 0x47FC, 0x7A99, 0xC8A2, 0xF5C7, 0xB268, 0x8F0D, 0xEB7B, 0xD61E, 0x91B1, 0xACD4, 0x1EEF, 0x238A, 0x6425, 0x5940, 0xACC9, 0x91AC, 0xD603, 0xEB66, 0x595D, 0x6438, 0x2397, 0x1EF2, 0x7A84, 0x47E1, 0x004E, 0x3D2B, 0x8F10, 0xB275, 0xF5DA, 0xC8BF, 0x23AD, 0x1EC8, 0x5967, 0x6402, 0xD639, 0xEB5C, 0xACF3, 0x9196, 0xF5E0, 0xC885, 0x8F2A, 0xB24F, 0x0074, 0x3D11, 0x7ABE, 0x47DB, 0xB252, 0x8F37, 0xC898, 0xF5FD, 0x47C6, 0x7AA3, 0x3D0C, 0x0069, 0x641F, 0x597A, 0x1ED5, 0x23B0, 0x918B, 0xACEE, 0xEB41, 0xD624, 0x7A6C, 0x4709, 0x00A6, 0x3DC3, 0x8FF8, 0xB29D, 0xF532, 0xC857, 0xAC21, 0x9144, 0xD6EB, 0xEB8E, 0x59B5, 0x64D0, 0x237F, 0x1E1A, 0xEB93, 0xD6F6, 0x9159, 0xAC3C, 0x1E07, 0x2362, 0x64CD, 0x59A8, 0x3DDE, 0x00BB, 0x4714, 0x7A71, 0xC84A, 0xF52F, 0xB280, 0x8FE5, 0x64F7, 0x5992, 0x1E3D, 0x2358, 0x9163, 0xAC06, 0xEBA9, 0xD6CC, 0xB2BA, 0x8FDF, 0xC870, 0xF515, 0x472E, 0x7A4B, 0x3DE4, 0x0081, 0xF508, 0xC86D, 0x8FC2, 0xB2A7, 0x009C, 0x3DF9, 0x7A56, 0x4733, 0x2345, 0x1E20, 0x598F, 0x64EA, 0xD6D1, 0xEBB4, 0xAC1B, 0x917E, 0x475A, 0x7A3F, 0x3D90, 0x00F5, 0xB2CE, 0x8FAB, 0xC804, 0xF561, 0x9117, 0xAC72, 0xEBDD, 0xD6B8, 0x6483, 0x59E6, 0x1E49, 0x232C, 0xD6A5, 0xEBC0, 0xAC6F, 0x910A, 0x2331, 0x1E54, 0x59FB, 0x649E, 0x00E8, 0x3D8D, 0x7A22, 0x4747, 0xF57C, 0xC819, 0x8FB6, 0xB2D3, 0x59C1, 0x64A4, 0x230B, 0x1E6E, 0xAC55, 0x9130, 0xD69F, 0xEBFA, 0x8F8C, 0xB2E9, 0xF546, 0xC823, 0x7A18, 0x477D, 0x00D2, 0x3DB7, 0xC83E, 0xF55B, 0xB2F4, 0x8F91, 0x3DAA, 0x00CF, 0x4760, 0x7A05, 0x1E73, 0x2316, 0x64B9, 0x59DC, 0xEBE7, 0xD682, 0x912D, 0xAC48 ]


class WMBusManufacturerField(LEShortField):
#FIX H2I
    def i2h(self, pkt, x):
        return chr(((x >> 10) & 0x001F) + 64) + chr(((x >> 5) & 0x001F) + 64) + chr((x & 0x001F) + 64)

    def h2i(self, pkt, x):
        return "\xAB\xCD"
        tab = [ord(c) - 64 for c in x]
        return struct.pack("<H", (tab[0] << 10) + (tab[1] << 5) + tab[2])


class WMBusManufacturerField1(LEShortEnumField):
    i2s={
        0: 'Other'
    }

    def __init__(self, name, default):
        Field.__init__(self, name, default, "2s")

    def i2h(self, pkt, x):
        temp = struct.unpack("<H", x)[0]
        return chr(((temp >> 10) & 0x001F) + 64) + chr(((temp >> 5) & 0x001F) + 64) + chr((temp & 0x001F) + 64)

    def h2i(self, pkt, x):
        tab = [ord(c) - 64 for c in x]
        return struct.pack("<H", (tab[0] << 10) + (tab[1] << 5) + tab[2])



class WMBusEncPayload(Raw):
    name = "WMBus Encrypted Payload"


class WMBusELLDecPayload(Packet):
    name = "WMBus Decrypted Payload"

    def pre_dissect(self,payload):
        print "try to dissect"
        a = self.underlayer.decrypt_payload(payload)
        print "dissected : " + a.encode("hex")
        return a

    def post_build(self, pkt, pay):
        return self.underlayer.encrypt_payload(pkt)


    def do_build_payload(self):
        self.raw_packet_cache = None
        return super(WMBusELLDecPayload, self).do_build_payload()


class WMBusDALDecPayload(WMBusELLDecPayload):
    name = "WMBus Decrypted Payload"

    fields_desc = [
        BitEnumField("dec_check",0,16, { 0x2F2F: "OK" } ),
        MBusData
    ]

    def post_build(self, pkt, pay):
        #Remove dec_check bytes before encryption
        return self.underlayer.encrypt_payload(pkt[2:])


class WMBusShortHeader(Packet):
    name = "WMBus ShortHeader"
    fields_desc = [
        ByteField("access_nr", 0),
        BitEnumField("error", 0, 2, SH_error_code),
        FlagsField("status", 0, 6, ["LowPow", "PermErr", "TempErr", "MfgSpec1", "MfgSpec2", "MfgSpec3"]),
        #CW[0]
        BitField("enc_blocks", 0, 4),
        BitField("content", 0, 2),
        BitField("hops", 0, 2),
        #CW[1]
        BitEnumField("accessibility", 0, 2, SH_access),
        BitEnumField("sync", 0, 1, ["Asynchronous Packet", "Synchronous (Periodical) Packet"]),
        HiddenField(BitField("unk", 0, 1),True),
        Emph(BitEnumField("enc", 0, 4, SH_encryption))
    ]

    def get_crypt_IV(self):


        pkt=self
        while True : #Search for WMBusLinkLayer in underlayers
            pkt=pkt.underlayer
            if isinstance(pkt, WMBusLinkLayer):
                break
            if not isinstance(pkt.underlayer,Packet):
                break

        if not isinstance(pkt, WMBusLinkLayer):
            return


        IV = struct.pack("<HI", pkt.getfieldval("manuf") ,pkt.getfieldval("addr") )
        
        if self.enc in [2, 3]: #DES CBC
            now = datetime.datetime.now()
            fmtG = (now.day & 0x1F) + (((now.year - 2000) & 0x7) << 5) + (now.month << 8) + (((now.year - 2000) >> 3) << 12)
            return IV + struct.pack("H",fmtG)
        if self.enc in [4, 5]: #AES CBC
            return IV + struct.pack("BB", pkt.getfieldval("version"), pkt.getfieldval("device") ) + struct.pack("B", self.getfieldval("access_nr")) * 8
        return

    def encrypt_payload(self,pay):

        if self.enc not in [2, 3, 4, 5]:
            return pay

        IV = self.get_crypt_IV()

        if not IV:
            print "Warning : No IV found"
            return pay

        key = scapy.config.conf.wmbuskey[IV[:6]]
        if self.enc == 2: #DES-CBC no iv
            IV = '\x00'*8
            return DES_CBC_ENCRYPT(pay,key,IV)
        if self.enc == 3: #DES-CBC with iv
            print DES_CBC_ENCRYPT(pay,key,IV).encode("hex")
            return DES_CBC_ENCRYPT(pay,key,IV)
        if self.enc == 4: #AES-CBC no iv
            IV = '\x00'*16
            return AES_CBC_ENCRYPT(pay,key,IV)
        if self.enc == 5: #AES-CBC with iv
            return AES_CBC_ENCRYPT(pay,key,IV)

    def decrypt_payload(self,pay):
        IV = self.get_crypt_IV()
        if not IV:
            print "Warning : No IV found"
            return pay

        key = scapy.config.conf.wmbuskey[IV[:6]]

        if self.enc == 2: #DES-CBC no iv
            IV = '\x00'*8
            return DES_CBC_DECRYPT(pay,key,IV)
        if self.enc == 3: #DES-CBC with iv:
            return DES_CBC_DECRYPT(pay,key,IV)
        if self.enc == 4: #AES-CBC no iv
            IV = '\x00'*16
            return AES_CBC_DECRYPT(pay,key,IV)
        if self.enc == 5: #AES-CBC with iv
            return AES_CBC_DECRYPT(pay,key,IV)

    def guess_payload_class(self, pay):

        if self.enc in [1, 6]:
            return WMBusEncPayload      #RFU crypto

        IV = self.get_crypt_IV()
        try:
            key = scapy.config.conf.wmbuskey[IV[:6]]
        except:
            key = ""

        if self.enc in [2, 3, 4, 5]:
            if not key:
                return WMBusEncPayload  #Couldn't be decrypted  
            else:
                return WMBusDALDecPayload  #Sucessfully decrypted
        return MBusData                 #Cleartext Payload





class WMBusLongHeader(Packet):
    name = "WMBus LongHeader"
    fields_desc = [
        LongField("id", 0),
        WMBusManufacturerField("manuf", 0),
        ByteField("version", 0),
        ByteEnumField("device", 0, LL_device_types),
        WMBusShortHeader
    ]








class WMBusExtLinkLayer_len2(Packet):
    name = "WMBus Extended linkLayer"
    fields_desc = [
        #ByteField("CC", 0),                                                #CC
        BitEnumField("B", 0, 1, ["Unidirectional", "Bidirectional"]),       #CC
        BitEnumField("D", 0, 1, ["Can wait", "Fast response needed"]),      #CC
        BitEnumField("S", 0, 1, ["Not Synchronized", "Synchronized"]),      #CC
        BitEnumField("H", 0, 1, ["Not Relayed", "Relayed"]),                #CC
        BitEnumField("P", 0, 1, ["Not Urgent", "Urgent"]),                  #CC
        BitEnumField("A", 0, 1, ["Limited Access", "Full Access"]),         #CC
        BitEnumField("R", 0, 1, ["First iteration", "Repeated Frame"]),     #CC
        BitEnumField("RFU", 0, 1, ["Unidirectional", "Bidirectional"]),     #CC
        ByteField("ACC", 0)                                                 #ACCess number
    ]


ELL_ENC = {
    0: "Clear Text",
    1: "AES128-CTR",
    2: "RFU",
    3: "RFU",
    4: "RFU",
    5: "RFU",
    6: "RFU",
    7: "RFU"
}


class WMBusExtLinkLayer_crypto(Packet):
    name = "WMBus Extended linkLayer"
    fields_desc = [
        Emph(BitEnumField("Enc", 0, 3, ELL_ENC)),           #SN
        BitField("Time", 0, 25),                            #SN
        BitField("Session", 0, 4)                           #SN
        #2bytes payload CRC
    ]

    def get_crypt_IV(self):
        """
        Counter fields from WMBus layer
        field       | M A CC SN FN BC
        size (o)    | 2 6  1  4  2  1
        """

        print "papapa"
        pkt=self
        while True : #Search for WMBusLinkLayer in underlayers
            pkt=pkt.underlayer
            if isinstance(pkt, WMBusLinkLayer):
                break
            if not isinstance(pkt.underlayer,Packet):
                break

        if not isinstance(pkt, WMBusLinkLayer):
            return
        print "papapa"

        if self.Enc : #AES CTR
            BC = 0
            FN = 0 #To incrment after each frame in a session

            CC = self.RFU + (self.R<<1) + (self.A<<2) + (self.P<<3) + (self.H<<4) + (self.S<<5) + (self.D<<6) + (self.B<<7)
                
            SN = self.Session + (self.Time<<4) + (self.Enc<<29)

            IV = struct.pack("<HIBIHB", pkt.getfieldval("manuf") ,pkt.getfieldval("addr"), CC, SN, FN ,BC)
            print "a"
            print IV.encode("hex")
            print "a"
            return IV

        return


    def guess_payload_class(self, pay):

        if self.Enc in [2, 3, 4, 5, 6, 7]:
            return WMBusEncPayload      #RFU crypto

        IV = self.get_crypt_IV()

        try:
            key = scapy.config.conf.wmbuskey[IV[:6]]
        except:
            key = ""

        print "key"
        print key.encode("hex")
        print "key"

        if self.Enc:
            if not key:
                return WMBusEncPayload  #Couldn't be decrypted  
            else:
                return WMBusELLDecPayload  #Sucessfully decrypted
        return MBusData                 #Cleartext Payload

    #CRC handling + crypto
    def pre_dissect(self, s):

        if isinstance(self,WMBusExtLinkLayer_len8):
            offset=6
        else :
            offset=14

        crc = s[offset:][:2]
        ###############################################TODO check CRC
        if len(crc) != 2:
            warning("ELL CRC error")
        without_crc = s[:offset] + s[offset+2:]

        return without_crc

    #CRC handling + crypto
    def post_build(self, p, pay):
        print "POSTUIBLD"
        print p.encode("hex")
        print pay.encode("hex")

        crc = self.crc16(pay)
        crc = '\xFF\xFF'
        #pay = struct.pack('>H',crc) + pay
        pay = crc + pay

        return p + pay

    def do_build_payload(self):
        self.raw_packet_cache = None        
        return super(WMBusExtLinkLayer_crypto, self).do_build_payload()


    def crc16(self, input):
        """ CRC-16 with input not reflected, reversed output & (16 + 13 + 12 + 11 + 10 + 8 + 6 + 5 + 2 + 0) polynom """

        crc = 0
        for curr in input:
            curr = ord(curr) & 0xFF

            crc = (crc ^ (curr << 8)) & 0xFFFF;
            pos = (crc >> 8) & 0xFF;
            crc = (crc << 8) & 0xFFFF;
            crc = (crc ^ crcTable[pos]) & 0xFFFF;
        return 0xFFFF-crc

    def encrypt_payload(self,pay):

        if not self.enc:
            return pay

        IV = self.get_crypt_IV()

        if not IV:
            print "Warning : No IV found"
            return pay

        key = scapy.config.conf.wmbuskey[IV[:6]]
        return AES_CTR_ENCRYPT(pay,key,IV)

    def decrypt_payload(self,pay):
        IV = self.get_crypt_IV()
        if not IV:
            print "Warning : No IV found"
            return pay

        key = scapy.config.conf.wmbuskey[IV[:6]]
        return AES_CTR_DECRYPT(pay,key,IV)


class WMBusExtLinkLayer_len8(WMBusExtLinkLayer_crypto):
    name = "WMBus Extended linkLayer 8"
    fields_desc = [
        WMBusExtLinkLayer_len2,
        WMBusExtLinkLayer_crypto
    ]

    def mysummary(self):
        return self.sprintf("WMBus Ext LL")



class WMBusExtLinkLayer_len10(Packet):
    name = "WMBus Extended linkLayer"
    fields_desc = [
        WMBusExtLinkLayer_len2,
        WMBusManufacturerField("M2", 0),                    #M2
        XLEIntField("addr", 0),                             #A2
        ByteField("version", 1),                            #A2
        ByteEnumField("device", 0, LL_device_types),        #A2
    ]

    def guess_payload_class(self, pay):
        return MBusData

    def mysummary(self):
        return self.sprintf("WMBus Ext LL (%WMBusExtLinkLayer_len10.device%)")

class WMBusExtLinkLayer_len16(WMBusExtLinkLayer_crypto):
    name = "WMBus Extended linkLayer"
    fields_desc = [
        WMBusExtLinkLayer_len10,
        WMBusExtLinkLayer_crypto
    ]

    def mysummary(self):
        return self.sprintf("WMBus Ext LL (%WMBusExtLinkLayer_len16.device%)")




######### LINK LAYER #########
class WMBusLinkLayer(Packet):
    
    fields_desc = [
        ByteField("len", None),                                 #L
        BitField("control_reserved", 0, 1),                     #C
        BitEnumField("direction", 0, 1, ["Reply", "Calling"]),  #C
        BitField("control", 0, 2),                              #C
        BitEnumField("func", 0, 4, LL_function_codes),          #C
        WMBusManufacturerField("manuf", 0),                     #M
        XLEIntField("addr", 0),                                 #A
        ByteField("version", 1),                                #A
        ByteEnumField("device", 0, LL_device_types),            #A
        ByteEnumField("ci", 0, LL_control_information)
    ]

    def guess_payload_class(self, pay):
        if self.ci == 0x8C:
            return WMBusExtLinkLayer_len2
        elif self.ci == 0x8D:
            return WMBusExtLinkLayer_len8
        elif self.ci == 0x8E:
            return WMBusExtLinkLayer_len10
        elif self.ci == 0x8F:
            return WMBusExtLinkLayer_len16
        elif self.ci in (0x61, 0x65, 0x6A, 0x6E, 0x74, 0x7A, 0x7B, 0x7D, 0x7F, 0x8A):
            return WMBusShortHeader     #Short Transport layer
        elif self.ci in (0x60, 0x64, 0x6B, 0x6F, 0x72, 0x73, 0x75, 0x7C, 0x7E, 0x80, 0x8B):
            return WMBusLongHeader      #Short Transport layer
        else :
            Packet.guess_payload_class(self, self)


    def crc16(self, input):
        """ CRC-16 with input not reflected, reversed output & (16 + 13 + 12 + 11 + 10 + 8 + 6 + 5 + 2 + 0) polynom """

        crc = 0
        for curr in input:
            curr = ord(curr) & 0xFF

            crc = (crc ^ (curr << 8)) & 0xFFFF;
            pos = (crc >> 8) & 0xFF;
            crc = (crc << 8) & 0xFFFF;
            crc = (crc ^ crcTable[pos]) & 0xFFFF;
        return 0xFFFF-crc


    def check_crc(self, payload):
        """ Two last bytes of payload is CRC, check CRC and return payload without CRC """
        
        calc = self.crc16(payload[:-2])
        print "crc : " + str(hex(calc)) + " on " + str(payload[:-2]).encode("hex")
        #check CRC
        return payload[:-2]


    def add_crc(self, payload):
        """ Two last bytes of payload is CRC, compute CRC and return payload with CRC """

        calc = self.crc16(payload[:])
        a= payload + struct.pack('>H',calc)
        #check CRC
        return a


    def decrypt(self, *args, **kwargs):
        IV = kwargs["iv"] if ("iv" in kwargs.keys()) else "" #get_crypt_IV() #find correct layer
        KEY = ""

        #Check for encrypted payload
        if not self.haslayer("WMBusEncPayload"):
            print "No encrypted layer in here !"
            return


        #Dedicated Application Layer
        try:
            if self.getfieldval("Enc"):
                return AES_CTR_DECRYPT(str(self["WMBusEncPayload"]),key,"") #TODO GET CTR
        except:
            pass

        #Extended link layer
        try:
            if self.getfieldval("Enc"):
                return AES_CTR_DECRYPT(str(self["WMBusEncPayload"]),key,"") #TODO GET CTR
        except:
            pass


        return



class WMBusLinkA(WMBusLinkLayer):
    name = "WMBus Link Frame A"

    def mysummary(self):
        return self.sprintf("WMBus LinkA (%WMBusLinkA.device%) #%WMBusLinkA.func%")

    def pre_dissect(self, s):

        offset=12
        if (len(s) < 12):
            print "Error, packet too short"

        #There is no CRC yet
        if len(s) == (ord(s[0]) + 1):
            print "no crc yet"
            return s

        without_crc=""
        without_crc += self.check_crc(s[0:offset]) #First time

        while True:
            if len( s[offset:offset+18] ):
                without_crc += self.check_crc(s[offset:offset+18])
            if offset >= len(s):
                break
            offset+=18

        return without_crc


    def post_build(self, p, pay):
        p += pay
        with_crc=""
        offset=10
        with_crc += self.add_crc(p[0:offset]) #First time
        while True:

            if len( p[offset:offset+16] ):
                with_crc += self.add_crc(p[offset:offset+16])
            if offset >= len(p):
                break
            offset+=16

        return with_crc

    def do_build_payload(self):
        self.raw_packet_cache = None        
        return super(WMBusLinkA, self).do_build_payload()




class WMBusLinkB(WMBusLinkLayer):
    name = "WMBus Link Frame B"

    def mysummary(self):
        return self.sprintf("WMBus LinkB (%WMBusLinkB.device%) #%WMBusLinkB.func%")

    def pre_dissect(self, s):
        offset=126
        if (len(s) < 13):
            print "Error, packet too short"
        """
        #There is no CRC yet
        if len(s) < (ord(s[0]) + 1):
            print len(s)
            print (ord(s[0]) + 1)
            print "no crc yet"
            return s
        """

        without_crc=""
        without_crc += self.check_crc(s[0:offset]) #First time

        while True:
            if len( s[offset:offset+118] ):
                without_crc += self.check_crc(s[offset:offset+118])
            if offset >= len(s):
                break
            offset+=118

        return without_crc


    def post_build(self, p, pay):
        p += pay
        with_crc=""
        offset=126
        with_crc += self.add_crc(p[0:offset]) #First time
        while True:

            if len( p[offset:offset+116] ):
                with_crc += self.add_crc(p[offset:offset+116])
            if offset >= len(p):
                break
            offset+=116
        return with_crc

    def do_build_payload(self):
        self.raw_packet_cache = None        
        return super(WMBusLinkB, self).do_build_payload()

