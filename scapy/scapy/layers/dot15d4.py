## This file is for use with Scapy
## See http://www.secdev.org/projects/scapy for more information
## Copyright (C) Ryan Speers <ryan@rmspeers.com> 2011-2012
## 2012-03-10 Roger Meyer <roger.meyer@csus.edu>: Added frames
## This program is published under a GPLv2 license

## Copyright (C) Airbus Defence and Space
## Adam Reziouk, Enzo Laurent and Jonathan-Christofer Demay
## This program is published under a GPLv2 license

"""
Wireless MAC according to IEEE 802.15.4.
"""

import re, struct

from scapy.packet import *
from scapy.fields import *

from scapy import main
try:
    from scapy.layers.sixlowpan import *
    from scapy.layers.zigbee import *
except ImportError:
    log_loading.info("Can't import sixlowpan or zigbee")

try:
    from scapy.crypto.AESCCMDot15d4 import *
except ImportError:
    log_loading.info("Can't import AESCCMDot15d4. Won't be able to decrypt 802.15.4.")


try:
    main.load_contrib('scanner_802_15_4')
    conf.nwdb = NetworkDataBase('Dot15d4 Scanner', xml='/tmp/nwdb.xml')
except:
    log_loading.info("Can't import Dot15d4 database.")

### Fields ###
class dot15d4AddressField(Field):
    def __init__(self, name, default, length_of=None, fmt="<H", adjust=None):
        Field.__init__(self, name, default, fmt)
        self.length_of=length_of
        if adjust != None:  self.adjust=adjust
        else:               self.adjust=lambda pkt,x:self.lengthFromAddrMode(pkt, x)
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
        if self.adjust(pkt, self.length_of) == 2:
            return s + struct.pack(self.fmt[0]+"H", val)
        elif self.adjust(pkt, self.length_of) == 8:
            return s + struct.pack(self.fmt[0]+"Q", val)
        else:
            return s
    def getfield(self, pkt, s):
        if self.adjust(pkt, self.length_of) == 2:
            return s[2:], self.m2i(pkt, struct.unpack(self.fmt[0]+"H", s[:2])[0])
        elif self.adjust(pkt, self.length_of) == 8:
            return s[8:], self.m2i(pkt, struct.unpack(self.fmt[0]+"Q", s[:8])[0])
        else:
            raise Exception('impossible case')
    def lengthFromAddrMode(self, pkt, x):
        pkttop = pkt
        while pkttop.underlayer is not None:
                try:
                        pkttop.getfieldval(x)
                except:
                        pkttop = pkttop.underlayer
                else:
                        break
        addrmode = pkttop.getfieldval(x)
        #print "Underlayer field value of", x, "is", addrmode
        if addrmode == 2: return 2
        elif addrmode == 3: return 8
        else: return 0


#class dot15d4Checksum(LEShortField,XShortField):
#    def i2repr(self, pkt, x):
#        return XShortField.i2repr(self, pkt, x)
#    def addfield(self, pkt, s, val):
#        return s
#    def getfield(self, pkt, s):
#        return s


### Layers ###

class Dot15d4(Packet):
    name = "802.15.4"
    fields_desc = [
                    HiddenField(BitField("fcf_reserved_1", 0, 1), True), #fcf p1 b1
                    BitEnumField("fcf_panidcompress", 0, 1, [False, True]),
                    BitEnumField("fcf_ackreq", 0, 1, [False, True]),
                    BitEnumField("fcf_pending", 0, 1, [False, True]),
                    BitEnumField("fcf_security", 0, 1, [False, True]), #fcf p1 b2
                    Emph(BitEnumField("fcf_frametype", 0, 3, {0:"Beacon", 1:"Data", 2:"Ack", 3:"Command"})),
                    BitEnumField("fcf_srcaddrmode", 0, 2, {0:"None", 1:"Reserved", 2:"Short", 3:"Long"}),  #fcf p2 b1
                    BitField("fcf_framever", 0, 2), # 00 compatibility with 2003 version; 01 compatible with 2006 version
                    BitEnumField("fcf_destaddrmode", 2, 2, {0:"None", 1:"Reserved", 2:"Short", 3:"Long"}), #fcf p2 b2
                    HiddenField(BitField("fcf_reserved_2", 0, 2), True),
                    Emph(ByteField("seqnum", 1)) #sequence number
                    ]

    def mysummary(self):
        return self.sprintf("802.15.4 %Dot15d4.fcf_frametype% ackreq(%Dot15d4.fcf_ackreq%) ( %Dot15d4.fcf_destaddrmode% -> %Dot15d4.fcf_srcaddrmode% ) Seq#%Dot15d4.seqnum%")

    def guess_payload_class(self, payload):
        if self.fcf_frametype == 0x00:      return Dot15d4Beacon
        elif self.fcf_frametype == 0x01:    return Dot15d4Data
        elif self.fcf_frametype == 0x02:    return Dot15d4Ack
        elif self.fcf_frametype == 0x03:    return Dot15d4Cmd
        else:                               return Packet.guess_payload_class(self, payload)

    def answers(self, other):
        if isinstance(other, Dot15d4):
            if self.fcf_frametype == 2: #ack
                if self.seqnum != other.seqnum: #check for seqnum matching
                    return 0
                elif other.fcf_ackreq == 1: #check that an ack was indeed requested
                    return 1
        return 0

    def post_build(self, p, pay):
        #This just forces destaddrmode to None for Ack frames.
        #TODO find a more elegant way to do this
        if self.fcf_frametype == 2 and self.fcf_destaddrmode != 0:
            self.fcf_destaddrmode = 0
            return str(self)
        else:
            return p + pay


class Dot15d4FCS(Dot15d4, Packet):
    '''
    This class is a drop-in replacement for the Dot15d4 class above, except
    it expects a FCS/checksum in the input, and produces one in the output.
    This provides the user flexibility, as many 802.15.4 interfaces will have an AUTO_CRC setting
    that will validate the FCS/CRC in firmware, and add it automatically when transmitting.
    '''
    def pre_dissect(self, s):
        """Called right before the current layer is dissected"""
        if (makeFCS(s[:-2]) != s[-2:]): #validate the FCS given
            warning("FCS on this packet is invalid or is not present in provided bytes.")
            if type(self.underlayer) == GnuradioPacket:
                self.underlayer.proto = 0 # invalid packet
            return s                    #if not valid, pretend there was no FCS present
        return s[:-2]                   #otherwise just disect the non-FCS section of the pkt

    def decrypt(self, key="", seclevel=1, xbee=0):

        if self.fcf_security == True:

            self.payload.payload.payload = dot15d4decrypt(self.payload.payload, key, seclevel, xbee)

        else:
            warning("This packet has not the security header, it will not be decrypted.")

    def encrypt(self, key="", seclevel=1, extendauth=1, xbee=0):

        if self.fcf_security == True and self.payload.payload.payload != None:

            head_packet = self.copy()
            head_packet.payload.payload.payload = ""
            head_packet = str(head_packet)[:-2] # Checksum to remove

            self.payload.payload.payload = dot15d4encrypt(self, head_packet, key, seclevel, extendauth, xbee)

        else:
            warning("This packet has not the security header, it will not be encrypted.")

    def post_build(self, p, pay):

        #Encrypt payload
        if self.fcf_security == True and self.payload.payload.payload != None:
            head_packet = self[Dot15d4Data].copy()
            head_packet.payload.payload = ""
            pay = str(head_packet)
            head_packet = p + pay

            pay += dot15d4encrypt(self, head_packet)
        
        #This just forces destaddrmode to None for Ack frames.
        #TODO find a more elegant way to do this
        if self.fcf_frametype == 2 and self.fcf_destaddrmode != 0:
            self.fcf_destaddrmode = 0
            return str(self)
        else:
            return p + pay + makeFCS(p+pay) #construct the packet with the FCS at the end

    def mysummary(self):
        return self.sprintf("802.15.4 %Dot15d4FCS.fcf_frametype% ackreq(%Dot15d4FCS.fcf_ackreq%) ( %Dot15d4FCS.fcf_destaddrmode% -> %Dot15d4FCS.fcf_srcaddrmode% ) Seq#%Dot15d4FCS.seqnum%")


class Dot15d4Ack(Packet):
    name = "802.15.4 Ack"
    fields_desc = [ ]

class Dot15d4AuxSecurityHeader(Packet):
    name = "802.15.4-2006 Auxiliary Security Header"
    fields_desc = [
        HiddenField(BitField("sec_sc_reserved", 0, 3), True),
        # Key Identifier Mode
        # 0: Key is determined implicitly from the originator and receipient(s) of the frame
        # 1: Key is determined explicitly from the the 1-octet Key Index subfield of the Key Identifier field
        # 2: Key is determined explicitly from the 4-octet Key Source and the 1-octet Key Index
        # 3: Key is determined explicitly from the 8-octet Key Source and the 1-octet Key Index
        BitEnumField("sec_sc_keyidmode", 0, 2, {
            0:"Implicit", 1:"1oKeyIndex", 2:"4o-KeySource-1oKeyIndex", 3:"8o-KeySource-1oKeyIndex"}
        ),
        BitEnumField("sec_sc_seclevel", 0, 3, {0:"None", 1:"MIC-32", 2:"MIC-64", 3:"MIC-128",          \
                                               4:"ENC", 5:"ENC-MIC-32", 6:"ENC-MIC-64", 7:"ENC-MIC-128"}),
        XIntField("sec_framecounter", 0x00000000), # 4 octets
        # Key Identifier (variable length): identifies the key that is used for cryptographic protection
        # Key Source : length of sec_keyid_keysource varies btwn 0, 4, and 8 bytes depending on sec_sc_keyidmode
        # 4 octets when sec_sc_keyidmode == 2
        ConditionalField(XLEIntField("sec_keyid_keysource", 0x00000000), 
            lambda pkt:pkt.getfieldval("sec_sc_keyidmode") == 2),
        # 8 octets when sec_sc_keyidmode == 3
        ConditionalField(LELongField("sec_keyid_keysource", 0x0000000000000000), 
            lambda pkt:pkt.getfieldval("sec_sc_keyidmode") == 3),
        # Key Index (1 octet): allows unique identification of different keys with the same originator
        ConditionalField(XByteField("sec_keyid_keyindex", 0xFF), 
            lambda pkt:pkt.getfieldval("sec_sc_keyidmode") != 0),
    ]

    def post_dissect(self, payload):

        if self.underlayer != None and self.underlayer.underlayer != None and payload != None:

            self.add_payload(payload)
            self.payload = dot15d4decrypt(self)


class Dot15d4AuxSecurityHeader2003(Packet):
    name = "802.15.4-2003 Auxiliary Security Header"
    fields_desc = [
        XIntField("sec_framecounter", 0x00000000), # 4 octets
        XByteField("sec_keyseqcounter", 0x00), # 1 octet
    ]

    def post_dissect(self, payload):

        if self.underlayer != None and self.underlayer.underlayer != None and payload != None:

            self.add_payload(payload)
            self.payload = dot15d4decrypt(self)


class Dot15d4Data(Packet):
    name = "802.15.4 Data"
    fields_desc = [
                    XLEShortField("dest_panid", 0xFFFF),
                    dot15d4AddressField("dest_addr", 0xFFFF, length_of="fcf_destaddrmode"),
                    ConditionalField(XLEShortField("src_panid", 0x0), \
                                        lambda pkt:util_srcpanid_present(pkt)),
                    ConditionalField(dot15d4AddressField("src_addr", None, length_of="fcf_srcaddrmode"), \
                                        lambda pkt:pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0),
                    ]
    def mysummary(self):
        return self.sprintf("802.15.4 Data ( %Dot15d4Data.src_panid%:%Dot15d4Data.src_addr% -> %Dot15d4Data.dest_panid%:%Dot15d4Data.dest_addr% )")

    def guess_payload_class(self, payload):

        if self.underlayer.getfieldval("fcf_security") == True:

            if self.underlayer.fcf_framever == 0x0:
                return Dot15d4AuxSecurityHeader2003
            else:
                return Dot15d4AuxSecurityHeader

        # 6LoWPAN
        #   011X XXXX = LoWPAN_IPHC
        #   0x41 = IPv6
        #   10XX XXXX or 11XX XXXX = Mesh, fragment etc... 
        elif ord(payload[0]) >> 5 == 0x3 or ord(payload[0]) == 0x41 or (ord(payload[0]) >> 6) >= 0x2:
            try:    
                return SixLoWPAN 
            except Exception, e: 
                return payload  
        # ZigBee
        # Protocol Version = 2
        # Discover route = (0 or 1)
        #elif ((ord(payload[0]) & 0x3C) >> 2) == 0x2 and (ord(payload[0]) >> 6) <= 0x1:
        #    try:   
        #        return ZigbeeNWK
        #    except Exception, e:
        #        return payload    
        else:
            return payload


class Dot15d4Beacon(Packet):
    name = "802.15.4 Beacon"
    fields_desc = [
                    XLEShortField("src_panid", 0x0),
                    dot15d4AddressField("src_addr", None, length_of="fcf_srcaddrmode"),
                    # Security field present if fcf_security == True
                    ConditionalField(PacketField("aux_sec_header", Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),
                        lambda pkt:pkt.underlayer.getfieldval("fcf_security") == True),

                    # Superframe spec field:
                    BitField("sf_sforder", 15, 4),      #not used by ZigBee
                    BitField("sf_beaconorder", 15, 4),  #not used by ZigBee
                    BitEnumField("sf_assocpermit", 0, 1, [False, True]),
                    BitEnumField("sf_pancoord", 0, 1, [False, True]),
                    BitField("sf_reserved", 0, 1),      #not used by ZigBee
                    BitEnumField("sf_battlifeextend", 0, 1, [False, True]), #not used by ZigBee
                    BitField("sf_finalcapslot", 15, 4), #not used by ZigBee

                    # GTS Fields
                    #  GTS Specification (1 byte)
                    BitEnumField("gts_spec_permit", 1, 1, [False, True]), #GTS spec bit 7, true=1 iff PAN cord is accepting GTS requests
                    BitField("gts_spec_reserved", 0, 4),  #GTS spec bits 3-6
                    BitField("gts_spec_desccount", 0, 3), #GTS spec bits 0-2
                    #  GTS Directions (0 or 1 byte)
                    ConditionalField(BitField("gts_dir_reserved", 0, 1), lambda pkt:pkt.getfieldval("gts_spec_desccount") != 0),
                    ConditionalField(BitField("gts_dir_mask", 0, 7), lambda pkt:pkt.getfieldval("gts_spec_desccount") != 0),
                    #  GTS List (variable size)
                    #TODO add a Packet/FieldListField tied to 3bytes per count in gts_spec_desccount

                    # Pending Address Fields:
                    #  Pending Address Specification (1 byte)
                    BitField("pa_num_short", 0, 3), #number of short addresses pending
                    BitField("pa_reserved_1", 0, 1),
                    BitField("pa_num_long", 0, 3), #number of long addresses pending
                    BitField("pa_reserved_2", 0, 1),
                    #  Address List (var length)
                    #TODO add a FieldListField of the pending short addresses, followed by the pending long addresses, with max 7 addresses
                    #TODO beacon payload
                    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Beacon ( %Dot15d4Beacon.src_panid%:%Dot15d4Beacon.src_addr% ) assocPermit(%Dot15d4Beacon.sf_assocpermit%) panCoord(%Dot15d4Beacon.sf_pancoord%)")

#    def guess_payload_class(self, payload):
#        return ZigBeeBeacon

class Dot15d4Cmd(Packet):
    name = "802.15.4 Command"
    fields_desc = [
                    XLEShortField("dest_panid", 0xFFFF),
                    # Users should correctly set the dest_addr field. By default is 0x0 for construction to work.
                    dot15d4AddressField("dest_addr", 0x0, length_of="fcf_destaddrmode"),
                    ConditionalField(XLEShortField("src_panid", 0x0),
                                        lambda pkt:util_srcpanid_present(pkt)),
                    ConditionalField(dot15d4AddressField("src_addr", None, length_of="fcf_srcaddrmode"), \
                                        lambda pkt:pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0),
                    # Security field present if fcf_security == True
                    ConditionalField(PacketField("aux_sec_header", Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),
                        lambda pkt:pkt.underlayer.getfieldval("fcf_security") == True),
                    ByteEnumField("cmd_id", 0, {
                        1:"AssocReq", # Association request
                        2:"AssocResp", # Association response
                        3:"DisassocNotify", # Disassociation notification
                        4:"DataReq", # Data request
                        5:"PANIDConflictNotify", # PAN ID conflict notification
                        6:"OrphanNotify", # Orphan notification
                        7:"BeaconReq", # Beacon request
                        8:"CoordRealign", # coordinator realignment
                        9:"GTSReq" # GTS request
                        # 0x0a - 0xff reserved
                    }),
                    #TODO command payload
                    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Command %Dot15d4Cmd.cmd_id% ( %Dot15dCmd.src_panid%:%Dot15d4Cmd.src_addr% -> %Dot15d4Cmd.dest_panid%:%Dot15d4Cmd.dest_addr% )")

    # command frame payloads are complete: DataReq, PANIDConflictNotify, OrphanNotify, BeaconReq don't have any payload
    # Although BeaconReq can have an optional ZigBee Beacon payload (implemented in ZigBeeBeacon)
    def guess_payload_class(self, payload):
        if   self.cmd_id == 1: return Dot15d4CmdAssocReq
        elif self.cmd_id == 2: return Dot15d4CmdAssocResp
        elif self.cmd_id == 3: return Dot15d4CmdDisassociation
        elif self.cmd_id == 8: return Dot15d4CmdCoordRealign
        elif self.cmd_id == 9: return Dot15d4CmdGTSReq
        else:                  return Packet.guess_payload_class(self, payload)

class Dot15d4CmdCoordRealign(Packet):
    name = "802.15.4 Coordinator Realign Command"
    fields_desc = [
        # PAN Identifier (2 octets)
        XLEShortField("panid", 0xFFFF),
        # Coordinator Short Address (2 octets)
        XLEShortField("coord_address", 0x0000),
        # Logical Channel (1 octet): the logical channel that the coordinator intends to use for all future communications
        ByteField("channel", 0),
        # Short Address (2 octets)
        XLEShortField("dev_address", 0xFFFF),
        # Channel page (0/1 octet) TODO optional
        #ByteField("channel_page", 0),
    ]
    def mysummary(self):
        return self.sprintf("802.15.4 Coordinator Realign Payload ( PAN ID: %Dot15dCmdCoordRealign.pan_id% : channel %Dot15d4CmdCoordRealign.channel% )")


### Utility Functions ###
def util_srcpanid_present(pkt):
    '''A source PAN ID is included if and only if both src addr mode != 0 and PAN ID Compression in FCF == 0'''
    if (pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0) and (pkt.underlayer.getfieldval("fcf_panidcompress") == 0): return True
    else: return False


def translate_seclevel_2003_to_2006(seclevel):
    # Corresponding Identifier Security Suite between IEEE 802.15.4-2003 and IEEE 802.15.4-2006
    table_seclevel = {
            0 : 0,  # None              -> None
            1 : 4,  # AES-CTR           -> ENC
            2 : 7,  # AES-CCM-128       -> ENC-MIC-128
            3 : 6,  # AES-CCM-64        -> ENC-MIC-64
            4 : 5,  # AES-CCM-32        -> ENC-MIC-32
            5 : 3,  # AES-CBC-MAC-128   -> MIC-128
            6 : 2,  # AES-CBC-MAC-64    -> MIC-64
            7 : 1   # AES-CBC-MAC-32    -> MIC-32
            }

    return table_seclevel[seclevel]


def dot15d4decrypt(pkt, key="", seclevel=1, xbee=0):


    if conf.use_dot15d4_database:

        text = str(pkt.payload)
        

        if conf.nwdb == None:
            
            try:
                conf.nwdb = NetworkDataBase('Dot15d4 Scanner', xml='/tmp/nwdb.xml')
            except:
                print 'Would not be able to decrypt packet because no dot15d4 database could have been loaded'
                return text
            
        
        key, security_conf = conf.nwdb.getSecurityConf(pkt.underlayer.src_addr,
                                                       pkt.underlayer.underlayer.fcf_panidcompress and pkt.underlayer.dest_panid or pkt.underlayer.src_panid,
                                                       pkt.underlayer.dest_addr,
                                                       pkt.underlayer.dest_panid,
                                                       pkt.underlayer.underlayer.fcf_srcaddrmode,
                                                       pkt.underlayer.underlayer.fcf_destaddrmode,
                                                       pkt.underlayer.underlayer.fcf_framever,
                                                       pkt.underlayer.underlayer.fcf_frametype
                                                   )



    
        if security_conf == None or key == '':
            print 'Would not be able to decrypt packet because no dot15d4 database could have been loaded'
            return text

        else:

            decrypted_text =  conf.nwdb.unsecure_frame(text, security_conf, pkt.underlayer.underlayer.fcf_framever, pkt, key)

            if decrypted_text != "" and (ord(decrypted_text[0]) >> 5 == 0x3 or ord(decrypted_text[0]) == 0x41 or (ord(decrypted_text[0]) >> 6) >= 0x2):
                
                try:
                    return SixLoWPAN(decrypted_text)
                except Exception, e:
                    return decrypted_text
                
            return decrypted_text

    else:

        key = getAESKey(key)

        seclevel, extendauth, xbee = getSec2003Config(seclevel, 0, xbee)

        text = str(pkt.payload)

        if key != "" and seclevel != 0:

            src_addr = pkt.underlayer.getfieldval("src_addr")
            frame_counter = pkt.sec_framecounter

            if pkt.underlayer.underlayer.fcf_framever == 1:
                seclevel = int(pkt.sec_sc_seclevel)
                key_seq_counter = None
            else:
                seclevel = translate_seclevel_2003_to_2006(seclevel)

                if xbee:
                    # XBee modules use 2006 specification to encrypt and decrypt packets
                    key_seq_counter = None
                else:
                    key_seq_counter = int(pkt.sec_keyseqcounter)           
                    
            decrypted_text = str(cipherDot15d4(text, key, seclevel, frame_counter, src_addr, key_seq_counter)) 

            if decrypted_text != "" and (ord(decrypted_text[0]) >> 5 == 0x3 or ord(decrypted_text[0]) == 0x41 or (ord(decrypted_text[0]) >> 6) >= 0x2):
                try:
                    return SixLoWPAN(decrypted_text)
                except Exception, e:
                    return decrypted_text

            elif decrypted_text != "" and ((ord(decrypted_text[0]) & 0x3C) >> 2) == 0x2 and (ord(decrypted_text[0]) >> 6) <= 0x1:
                try:
                    return ZigbeeNWK(decrypted_text)
                except Exception, e:
                    return decrypted_text                
            else:
                return decrypted_text

        else:
            return text


def dot15d4encrypt(pkt, header="", key="", seclevel=1, extendauth=1, xbee=0):



    if conf.use_dot15d4_database:

        text = str(pkt.payload.payload.payload)

        if conf.nwdb == None:
            
            try:
                conf.nwdb = NetworkDataBase('Dot15d4 Scanner', xml='/tmp/nwdb.xml')
            except:
                print 'Would not be able to decrypt packet because no dot15d4 database could have been loaded'
                return text
            
        key, security_conf = conf.nwdb.getSecurityConf(pkt.src_addr,
                                                       pkt.fcf_panidcompress and pkt.dest_panid or pkt.src_panid,
                                                       pkt.dest_addr,
                                                       pkt.dest_panid,
                                                       pkt.fcf_srcaddrmode,                                                       pkt.fcf_destaddrmode,
                                                       pkt.fcf_framever,
                                                       pkt.fcf_frametype
                                                   )

        if security_conf == None or key == '':
            print 'Would not be able to decrypt packet because no dot15d4 database could have been loaded'
            return text

        else:

            encrypted_text =  conf.nwdb.secure_frame(text, security_conf, pkt.fcf_framever, pkt, key, header)

            return encrypted_text




    else:

        key = getAESKey(key)

        seclevel, extendauth, xbee = getSec2003Config(seclevel, extendauth, xbee)
        
        text = str(pkt.payload.payload.payload)

        if key != "" and seclevel != 0:

            src_addr = pkt[Dot15d4Data].src_addr
            #src_addr = 0x158d0000540591

            if pkt.fcf_framever == 1:
                frame_counter = pkt[Dot15d4AuxSecurityHeader].sec_framecounter
                seclevel = int(pkt.sec_sc_seclevel)
                key_seq_counter = None
            else:
                frame_counter = pkt[Dot15d4AuxSecurityHeader2003].sec_framecounter
                seclevel = int(translate_seclevel_2003_to_2006(seclevel))
            
                if xbee:
                    # XBee modules use 2006 specification to encrypt and decrypt packets
                    key_seq_counter = None
                else:
                    key_seq_counter = int(pkt.sec_keyseqcounter)

                    if extendauth == 0 :
                        # The security header must be removed
                        header = header[:-5]
        
            encrypted_text = str(cipherDot15d4(text, key, seclevel, frame_counter, src_addr, key_seq_counter, header))

            return encrypted_text
        else:
            return text


def getAESKey(key=""):
    # Key
    if key == "":
        try:
            key = conf.dot15d4key
        except Exception, e:
            pass
    if len(key) != 32 and key != "":
        warning("The length of the key must do 16 bytes")

    return key

def getSec2003Config(securitysuite=1, extendauth=1, xbee=0):

    # Seclevel
    if type(securitysuite) == str:
        securitysuite = int(securitysuite)

    if securitysuite == 1:
        try:
            securitysuite = int(conf.dot15d4securitysuite)
        except Exception, e:
            pass
    if securitysuite > 7:
        warning("The security suite must be an interger between 0 and 7")

    # Extend Authentication data
    if type(extendauth) == str:
        extendauth = int(extendauth)

    if extendauth == 1:
        try:
            extendauth = int(conf.dot15d4extendauth)
        except Exception, e:
            pass
    if extendauth > 1:
        warning("Extended authentication data parameter must be a boolean (value: 0 or 1)")

    # Xbee
    if type(xbee) == str:
        xbee = int(xbee)

    if xbee == 0:
        try:
            xbee = int(conf.xbee)
        except Exception, e:
            pass
    if xbee > 1:
        warning("XBee parameter must be a boolean (value: 0 or 1)")
    
    return securitysuite, extendauth, xbee


# Do a CRC-CCITT Kermit 16bit on the data given
# Returns a CRC that is the FCS for the frame
#  Implemented using pseudocode from: June 1986, Kermit Protocol Manual
#  See also: http://regregex.bbcmicro.net/crc-catalogue.htm#crc.cat.kermit
def makeFCS(data):
    crc = 0
    for i in range(0, len(data)):
        c = ord(data[i])
        q = (crc ^ c) & 15              #Do low-order 4 bits
        crc = (crc // 16) ^ (q * 4225)
        q = (crc ^ (c // 16)) & 15      #And high 4 bits
        crc = (crc // 16) ^ (q * 4225)
    return struct.pack('<H', crc) #return as bytes in little endian order


class Dot15d4CmdAssocReq(Packet):
    name = "802.15.4 Association Request Payload"
    fields_desc = [
        BitField("allocate_address", 0, 1), # Allocate Address
        BitField("security_capability", 0, 1), # Security Capability
        BitField("reserved2", 0, 1), #  bit 5 is reserved
        BitField("reserved1", 0, 1), #  bit 4 is reserved
        BitField("receiver_on_when_idle", 0, 1), # Receiver On When Idle
        BitField("power_source", 0, 1), # Power Source
        BitField("device_type", 0, 1), # Device Type
        BitField("alternate_pan_coordinator", 0, 1), # Alternate PAN Coordinator
    ]
    def mysummary(self):
        return self.sprintf("802.15.4 Association Request Payload ( Alt PAN Coord: %Dot15d4CmdAssocReq.alternate_pan_coordinator% Device Type: %Dot15d4CmdAssocReq.device_type% )")

class Dot15d4CmdAssocResp(Packet):
    name = "802.15.4 Association Response Payload"
    fields_desc = [
        XLEShortField("short_address", 0xFFFF), # Address assigned to device from coordinator (0xFFFF == none)
        # Association Status
        # 0x00 == successful
        # 0x01 == PAN at capacity
        # 0x02 == PAN access denied
        # 0x03 - 0x7f == Reserved
        # 0x80 - 0xff == Reserved for MAC primitive enumeration values
        ByteEnumField("association_status", 0x00, {0:'successful', 1:'PAN_at_capacity', 2:'PAN_access_denied'}),
    ]
    def mysummary(self):
        return self.sprintf("802.15.4 Association Response Payload ( Association Status: %Dot15d4CmdAssocResp.association_status% Assigned Address: %Dot15d4CmdAssocResp.short_address% )")

class Dot15d4CmdDisassociation(Packet):
    name = "802.15.4 Disassociation Notification Payload"
    fields_desc = [
        # Disassociation Reason 
        # 0x00 == Reserved
        # 0x01 == The coordinator wishes the device to leave the PAN
        # 0x02 == The device wishes to leave the PAN
        # 0x03 - 0x7f == Reserved
        # 0x80 - 0xff == Reserved for MAC primitive enumeration values
        ByteEnumField("disassociation_reason", 0x02, {1:'coord_wishes_device_to_leave', 2:'device_wishes_to_leave'}),
    ]
    def mysummary(self):
        return self.sprintf("802.15.4 Disassociation Notification Payload ( Disassociation Reason %Dot15d4CmdDisassociation.disassociation_reason% )")

class Dot15d4CmdGTSReq(Packet):
    name = "802.15.4 GTS request command"
    fields_desc = [
        # GTS Characteristics field (1 octet)
        # Reserved (bits 6-7)
        BitField("reserved", 0, 2), 
        # Characteristics Type (bit 5)
        BitField("charact_type", 0, 1), 
        # GTS Direction (bit 4)
        BitField("gts_dir", 0, 1), 
        # GTS Length (bits 0-3)
        BitField("gts_len", 0, 4), 
    ]
    def mysummary(self):
        return self.sprintf("802.15.4 GTS Request Command ( %Dot15d4CmdGTSReq.gts_len% : %Dot15d4CmdGTSReq.gts_dir% )")


### Bindings ###
bind_layers( Dot15d4, Dot15d4Beacon, fcf_frametype=0)
bind_layers( Dot15d4, Dot15d4Data, fcf_frametype=1)
bind_layers( Dot15d4, Dot15d4Ack,  fcf_frametype=2)
bind_layers( Dot15d4, Dot15d4Cmd,  fcf_frametype=3)
bind_layers( Dot15d4FCS, Dot15d4Beacon, fcf_frametype=0)
bind_layers( Dot15d4FCS, Dot15d4Data, fcf_frametype=1)
bind_layers( Dot15d4FCS, Dot15d4Ack,  fcf_frametype=2)
bind_layers( Dot15d4FCS, Dot15d4Cmd,  fcf_frametype=3)

### DLT Types ###
conf.l2types.register(195, Dot15d4FCS)
conf.l2types.register(230, Dot15d4)
