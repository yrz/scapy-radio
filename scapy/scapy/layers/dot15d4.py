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
import json

from scapy.packet import *
from scapy.fields import *

try:
    from scapy.layers.sixlowpan import *
    from scapy.layers.zigbee import *
except ImportError:
    log_loading.info("Can't import sixlowpan or zigbee")

try:
    from scapy.crypto.AESCCMDot15d4 import *
except ImportError:
    log_loading.info("Can't import AESCCMDot15d4. Won't be able to decrypt 802.15.4.")


### Fields ###
class dot15d4AddressField(Field):

    __slots__ = ["length_of", "adjust"]

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
        if addrmode == 2: return 2
        elif addrmode == 3: return 8
        else: return 0


# Overloading ConditialField : When forging a packet by providing a string as an argument,
# conditional fields whose conditions are not True are overloaded by None (in fields).
# Thus, the default value is lost!
class MyConditionalField(ConditionalField):

    def getfield(self, pkt, s):
        if self._evalcond(pkt):
            return self.fld.getfield(pkt,s)
        else:
            return s,self.fld.default # OLD RETURNED VALUE WAS : return s, None

    
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
        XLEIntField("sec_framecounter", 0x00000000), # 4 octets
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
        
    def guess_payload_class(self, payload):
        return Padding

class Dot15d4AuxSecurityHeader2003(Packet):
    name = "802.15.4-2003 Auxiliary Security Header"
    fields_desc = [
        XLEIntField("sec_framecounter", 0), # 4 octets
        XByteField("sec_keyseqcounter", 0), # 1 octet
    ]

    def guess_payload_class(self, payload):
        return Padding

### Layers ###

class Dot15d4(Packet):

    name = "802.15.4"
    fields_desc = [
        #Frame control field: 2-bytes lenght
        BitField("fcf_reserved_1", 0, 1),
        BitEnumField("fcf_panidcompress", 0, 1, [False, True]),
        BitEnumField("fcf_ackreq", 0, 1, [False, True]),
        BitEnumField("fcf_pending", 0, 1, [False, True]),
        BitEnumField("fcf_security", 0, 1, [False, True]),
        Emph(BitEnumField("fcf_frametype", 0, 3, {0:"Beacon", 1:"Data", 2:"Ack", 3:"Command"})),
        BitEnumField("fcf_srcaddrmode", 0, 2, {0:"None", 1:"Reserved", 2:"Short", 3:"Long"}),
        BitField("fcf_framever", 0, 2), # 00 compatibility with 2003 version; 01 compatible with 2006 version
        BitEnumField("fcf_destaddrmode", 0, 2, {0:"None", 1:"Reserved", 2:"Short", 3:"Long"}),
        BitField("fcf_reserved_2", 0, 2),

        #Sequence number: 1-byte length
        Emph(ByteField("seqnum", 1)),

        #Addressing information fields: variable length
        ConditionalField(XLEShortField("dest_panid", 0xFFFF),\
                         lambda pkt: pkt.fcf_frametype in [1,3] and pkt.fcf_destaddrmode != 0),
        ConditionalField(dot15d4AddressField("dest_addr", 0xFFFF, length_of="fcf_destaddrmode"),\
                         lambda pkt: pkt.fcf_frametype in [1,3] and pkt.getfieldval("fcf_destaddrmode") != 0),
        ConditionalField(XLEShortField("src_panid", 0x0),\
                         lambda pkt: pkt.fcf_frametype != 2 and util_srcpanid_present(pkt)),
        ConditionalField(dot15d4AddressField("src_addr", 0x0, length_of="fcf_srcaddrmode"),\
                         lambda pkt:  pkt.fcf_frametype != 2 and pkt.getfieldval("fcf_srcaddrmode") != 0),
        
        
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 %Dot15d4.fcf_frametype% ackreq(%Dot15d4.fcf_ackreq%) ( %Dot15d4.fcf_destaddrmode% -> %Dot15d4.fcf_srcaddrmode% ) Seq#%Dot15d4.seqnum%")

    def guess_payload_class(self, payload):

        if self.fcf_frametype == 0x00:
            return Dot15d4Beacon
        elif self.fcf_frametype == 0x01:
            return Dot15d4Data
        elif self.fcf_frametype == 0x02:
            return Dot15d4Ack
        elif self.fcf_frametype == 0x03:
            return Dot15d4Cmd

    def answers(self, other):
        if isinstance(other, Dot15d4):
            if self.fcf_frametype == 2: #ack
                if self.seqnum != other.seqnum: #check for seqnum matching
                    return 0
                elif other.fcf_ackreq == 1: #check that an ack was indeed requested
                    return 1
        return 0


class Dot15d4FCS(Dot15d4, Packet):
    '''
    This class is a drop-in replacement for the Dot15d4 class above, except
    it expects a FCS/checksum in the input, and produces one in the output.
    This provides the user flexibility, as many 802.15.4 interfaces will have an AUTO_CRC setting
    that will validate the FCS/CRC in firmware, and add it automatically when transmitting.
    '''
    def post_build(self, p, pay):
        # Adding FCS
        return p + pay + makeFCS(p+pay) 


    def pre_dissect(self, s):
        """Called right before the current layer is dissected"""

        if (makeFCS(s[:-2]) != s[-2:]): #validate the FCS given
            warning("FCS on this packet is invalid or is not present in provided bytes.")
            if type(self.underlayer) == GnuradioPacket:
                self.underlayer.proto = 0 # invalid packet
            return s
        return s[:-2]


    # Overloading do_build_payload: Trick to fix post_build related problem
    def do_build_payload(self):
        self.raw_packet_cache = None 
        return super(Dot15d4FCS, self).do_build_payload()


    def get_mhr(self):
        return self.self_build()


    def secure(self, key='', seclevel=None, **devs):

        if self.fcf_security and self.payload != NoPayload():

            self.payload.secure(key, seclevel, **devs)


    def unsecure(self, key='', seclevel=None, **devs):

        if self.fcf_security and self.payload != NoPayload():

            self.payload.unsecure(key, seclevel, **devs)
            

class _CommonMAC(Packet):


    def post_build(self, p, pay):

        if isinstance(self.underlayer, Dot15d4) and self.underlayer.fcf_security:

            if not isinstance(self.payload, SecuredPayload):

                if conf.dot15d4auto_secure and self.security_material_available():

                    header = self.underlayer.get_mhr() + self.get_nonpayload_fields()
                    pay = self.dot15d4secure(pay, header)

            else:

                warning('Securing packet: conf.dot15d4auto_secure is True but packet is already secured!')
                
        return p + pay


    def post_dissect(self, s):

        # Unsecure frame if needed
        if isinstance(self.underlayer, Dot15d4) and self.underlayer.fcf_security:
            
            if conf.dot15d4auto_unsecure and self.security_material_available():

                header = self.underlayer.get_mhr() + self.get_nonpayload_fields()
                return self.dot15d4unsecure(s, header)

        return s


    def secure(self, key='', seclevel=None, **devs):

        if self.payload != NoPayload() and self.underlayer.fcf_security:

            if isinstance(self.payload, SecuredPayload):
                warning('Securing packet: Packet is already secured!')
                return

            if not self.security_material_available(key, seclevel):
                return
            
            header = self.underlayer.get_mhr() + self.get_nonpayload_fields()
            pay = self.get_payload_fields()
            ciphertext = self.dot15d4secure(pay, header, key, seclevel, **devs)

            if ciphertext != None:

                sec_cls = self.get_secured_class()
                sec_pay = sec_cls(ciphertext, _underlayer=self)
                self.remove_payload()
                self.add_payload(sec_pay)
                

    def unsecure(self, key='', seclevel=None, **devs):

        if self.payload != NoPayload() and self.underlayer.fcf_security:

            if not isinstance(self.payload, SecuredPayload):
                warning('Unsecuring packet: Packet is already unsecured!')
                return

            if not self.security_material_available(key, seclevel):
                return

            header = self.underlayer.get_mhr() + self.get_nonpayload_fields()
            pay = self.get_payload_fields()
            cleartext = self.dot15d4unsecure(pay, header, key, seclevel, **devs)

            if cleartext != None:

                unsec_cls = self.get_unsecured_class(cleartext)
                unsec_pay = unsec_cls(cleartext, _underlayer=self)
                self.remove_payload()
                self.add_payload(unsec_pay)
                

    def get_nonpayload_fields(self):
        return self.self_build()

    
    def get_payload_fields(self):
        return str(self.payload)

    
    def security_material_available(self, key='', seclevel=None):

        use_database = conf.dot15d4use_database

        if use_database:

            if conf.dot15d4_database != None:

                if dot15d4_db_security_material_available(self, conf.dot15d4_database):
                    return True
                else:
                    warning('Could not find security material to secure/unsecure frame into dot15d4 database! Trying default security material!')

            else:
                    warning('Could not find dot15d4 database! Load one by using "load_dot15d4_database(path)" method. Trying default security material!')
                    
            
        # Looking for default settings 

        if self.underlayer.fcf_srcaddrmode != 3: # Extended address (64bits)

            if conf.dot15d4_use_default_address==1 and conf.dot15d4_default_extended_address != None:
                srcaddr64 = conf.dot15d4_default_extended_address
                pass
            else:
                warning('Extended source address needed to unsecure frame')
                return False

        else:
            srcaddr64 = self.underlayer.src_addr

        if conf.dot15d4_use_maleability and conf.dot15d4_keystreams != None:

            if self.underlayer.fcf_framever == 0:

                if conf.dot15d4_keystreams.has_key((str(srcaddr64) + '_' + str(self.aux_sec_header_2003.sec_framecounter) + '_' + str(self.aux_sec_header_2003.sec_keyseqcounter))):

                    return True
                
            else:
                
                if conf.dot15d4_keystreams.has_key((str(srcaddr64) + '_' + str(self.aux_sec_header.sec_framecounter))):
                    
                    return True


        key = getAESKey(key)

        if key == None:
            warning('AES Key needed to unsecure frame')
            return False

        if self.underlayer.fcf_framever == 0:
            # 2003 frame
            seclevel = getSec2003Config(seclevel)
            if seclevel == None:
                warning("Could not get the 2003 security level needed to secure/unsecure frame")
                return False

        return True


    def dot15d4unsecure(self, ciphertext, header, key='', seclevel=None, **devs):

        if not isinstance(self.underlayer, Dot15d4):
            return

        use_database = conf.dot15d4use_database

        deviations = devs
        secconf = None
        
        if use_database:

            if conf.dot15d4_database != None:
        
                secconf = dot15d4_db_get_security_material(self, conf.dot15d4_database)

                if secconf != None:
                
                    key = secconf[0][2:]
                    srcaddr64 = secconf[1]
                    seclevel = secconf[2]
                    deviations = secconf[3]

                    if self.underlayer.fcf_framever == 1:
                        self.aux_sec_header.sec_sc_seclevel = seclevel

                else:
                    warning('Security material not found in dot15d4 database! Looking for default material!')


            else:
                    warning('Could not find dot15d4 database! Load one by using "load_dot15d4_database(path)" method. Trying default security material!')
        

        if secconf == None:
                
            if self.underlayer.fcf_srcaddrmode == 3: # Extended address (64bits)
                srcaddr64 = self.underlayer.src_addr
            else:
                if conf.dot15d4_use_default_address==1 and conf.dot15d4_default_extended_address != None:
                    srcaddr64 = conf.dot15d4_default_extended_address
                else:
                    warning('Extended source address needed to unsecure frame')
                    return

        # Maleability
        if conf.dot15d4_use_maleability and conf.dot15d4_keystreams != None:

            try:

                if self.underlayer.fcf_framever == 0:

                    if conf.dot15d4_keystreams.has_key((str(srcaddr64) + '_' + str(self.aux_sec_header_2003.sec_framecounter) + '_' + str(self.aux_sec_header_2003.sec_keyseqcounter))):

                        return maleabilityDot15d4(ciphertext, conf.dot15d4_keystreams.get((str(srcaddr64) + '_' + str(self.aux_sec_header_2003.sec_framecounter) + '_' + str(self.aux_sec_header_2003.sec_keyseqcounter))))
                    
                else:

                    if conf.dot15d4_keystreams.has_key((str(srcaddr64) + '_' + str(self.aux_sec_header.sec_framecounter))):

                        return maleabilityDot15d4(ciphertext, conf.dot15d4_keystreams.get((str(srcaddr64) + '_' + str(self.aux_sec_header.sec_framecounter))))

            except:

                return


        key = getAESKey(key)

        if key == None:
            warning('AES Key needed to unsecure frame')
            return 
            
        # 2003-frame 
        if self.underlayer.fcf_framever == 0:
        
            seclevel = getSec2003Config(seclevel)
                
            if seclevel == None:
                warning('Valid 2003 security level needed to unsecure frame')
                return 

            frame_counter = self.aux_sec_header_2003.sec_framecounter
            key_seq_counter = self.aux_sec_header_2003.sec_keyseqcounter

        # Securing 2006-frame
        elif self.underlayer.fcf_framever == 1:

            seclevel = self.aux_sec_header.sec_sc_seclevel
            frame_counter = self.aux_sec_header.sec_framecounter
            key_seq_counter = None

        else:
            warning('Invalid frame version. Cannot unsecure frame')
            return 
    
        cleartext = cipherDot15d4Unsecure(ciphertext, header, key, seclevel, frame_counter, srcaddr64, key_seq_counter, **deviations)[0]
        
        return cleartext



    def dot15d4secure(self, cleartext, header, key='', seclevel=None, **devs):
            
        if not isinstance(self.underlayer, Dot15d4):
            return

        use_database = conf.dot15d4use_database

        deviations = devs
        secconf = None
        
        if use_database:

            if conf.dot15d4_database != None:
        
                secconf = dot15d4_db_get_security_material(self, conf.dot15d4_database)

                if secconf != None:
                
                    key = secconf[0][2:]
                    srcaddr64 = secconf[1]
                    seclevel = secconf[2]
                    deviations = secconf[3]

                    if self.underlayer.fcf_framever == 1:
                        self.aux_sec_header.sec_sc_seclevel = seclevel

                else:
                    warning('Security material not found in dot15d4 database! Looking for default material!')

            else:
                    warning('Could not find dot15d4 database! Load one by using "load_dot15d4_database(path)" method. Trying default security material!')


        if secconf == None:
                
            if self.underlayer.fcf_srcaddrmode == 3: # Extended address (64bits)
                srcaddr64 = self.underlayer.src_addr
            else:

                if conf.dot15d4_use_default_address==1 and conf.dot15d4_default_extended_address != None:
                    srcaddr64 = conf.dot15d4_default_extended_address
                else:
                    warning('Extended source address needed to secure frame')
                    return


        # Maleability 
        if conf.dot15d4_use_maleability and conf.dot15d4_keystreams != None:

            try:

                if self.underlayer.fcf_framever == 0:

                    if conf.dot15d4_keystreams.has_key((str(srcaddr64) + '_' + str(self.aux_sec_header_2003.sec_framecounter) + '_' + str(self.aux_sec_header_2003.sec_keyseqcounter))):

                        return maleabilityDot15d4(cleartext, conf.dot15d4_keystreams.get((str(srcaddr64) + '_' + str(self.aux_sec_header_2003.sec_framecounter) + '_' + str(self.aux_sec_header_2003.sec_keyseqcounter))))
                    
                else:

                    if conf.dot15d4_keystreams.has_key((str(srcaddr64) + '_' + str(self.aux_sec_header.sec_framecounter))):

                        return maleabilityDot15d4(cleartext, conf.dot15d4_keystreams.get((str(srcaddr64) + '_' + str(self.aux_sec_header.sec_framecounter))))


            except:

                return
                    

        key = getAESKey(key)

        if key == None:
            warning('AES Key needed to secure frame')
            return 
            
        # 2003-frame 
        if self.underlayer.fcf_framever == 0:
        
            seclevel = getSec2003Config(seclevel)
                
            if seclevel == None:
                warning('Valid 2003 security level needed to secure frame')
                return 

            frame_counter = self.aux_sec_header_2003.sec_framecounter
            key_seq_counter = self.aux_sec_header_2003.sec_keyseqcounter

        # Securing 2006-frame
        elif self.underlayer.fcf_framever == 1:

            seclevel = self.aux_sec_header.sec_sc_seclevel
            frame_counter = self.aux_sec_header.sec_framecounter
            key_seq_counter = None

        else:
            warning('Invalid frame version. Cannot secure frame')
            return 
    
        ciphertext = cipherDot15d4Secure(cleartext, header, key, seclevel, frame_counter, srcaddr64, key_seq_counter, **deviations)
        
        return ciphertext


class Dot15d4Ack(Packet):

    name = "802.15.4 Ack"
    fields_desc = [ ]


''' TEST purpose +++  '''
class TEST(Packet):

    fields_desc = [XLEIntField('test', 0)]
''' TEST purpose --- '''


class Dot15d4Data(_CommonMAC):

    name = "802.15.4 Data"
    fields_desc = [

        #Security headers: 2003 or 2006
        #2006
        MyConditionalField(PacketField('aux_sec_header', Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),\
                         lambda pkt: (pkt.underlayer != None) and pkt.underlayer.fcf_security and pkt.underlayer.fcf_framever),
        #2003
        MyConditionalField(PacketField('aux_sec_header_2003', Dot15d4AuxSecurityHeader2003(), Dot15d4AuxSecurityHeader2003),\
                         lambda pkt: (pkt.underlayer != None) and pkt.underlayer.fcf_security and not pkt.underlayer.fcf_framever),

    ]

    def guess_payload_class(self, payload):

        if isinstance(self.underlayer, Dot15d4) and self.underlayer.fcf_security:
            
            if conf.dot15d4auto_unsecure and self.security_material_available():
                # if there, that means that frame has been unsecured in post_dissect

                ''' TEST purpose +++  '''                
                if ord(payload[0]) >> 3 == 0x18:
                    return SixLoWPAN
                elif ord(payload[0]) >> 3 == 0x1C:
                    return SixLoWPAN
                elif ord(payload[0]) >> 6 == 0x02:
                    return SixLoWPAN
                elif ord(payload[0]) == 0x41:
                    return SixLoWPAN
                elif ord(payload[0]) >> 5 == 0x03:
                    return SixLoWPAN
                            
                return DataUnsecuredPayload

            else:
                return DataSecuredPayload

        else:

            if ord(payload[0]) >> 3 == 0x18:
                return SixLoWPAN
            elif ord(payload[0]) >> 3 == 0x1C:
                return SixLoWPAN
            elif ord(payload[0]) >> 6 == 0x02:
                return SixLoWPAN
            elif ord(payload[0]) == 0x41:
                return SixLoWPAN
            elif ord(payload[0]) >> 5 == 0x03:
                return SixLoWPAN
            
            return DataPayload

                    
    def get_secured_class(self):

        return DataSecuredPayload


    def get_unsecured_class(self, pay):

        if ord(pay[0]) >> 3 == 0x18:
            return SixLoWPAN
        elif ord(pay[0]) >> 3 == 0x1C:
            return SixLoWPAN
        elif ord(pay[0]) >> 6 == 0x02:
            return SixLoWPAN
        elif ord(pay[0]) == 0x41:
            return SixLoWPAN
        elif ord(pay[0]) >> 5 == 0x03:
            return SixLoWPAN

        return DataUnsecuredPayload
        
class DataPayload(Raw):
    name = '802.15.4 Data payload'
    
# BEACON RELATED MATERIAL +++
    
class GTSDescriptor(Packet):

    name = 'GTS Descriptor'

    fields_desc = [

        dot15d4AddressField("gts_addr", 0, adjust=lambda pkt, x: 2),
        BitField("gts_start", 0, 4),
        BitField("gts_len", 0, 4),
    ]

    def guess_payload_class(self, payload):
        return Padding
    

class GTSFields(Packet):

    name = "GTS Fields"

    fields_desc = [

        #  GTS Specification (1 byte)
        BitEnumField("gts_spec_permit", 1, 1, [False, True]),
        BitField("gts_spec_reserved", 0, 4),  
        BitField("gts_spec_desccount", 0, 3),

        #  GTS Directions (0 or 1 byte)
        ConditionalField(BitField("gts_dir_reserved", 0, 1), lambda pkt:pkt.getfieldval("gts_spec_desccount") != 0),
        ConditionalField(BitField("gts_dir_mask", 0, 7), lambda pkt:pkt.getfieldval("gts_spec_desccount") != 0),

        #  GTS List (variable size)
        ConditionalField(PacketField('gts_desc1', GTSDescriptor(), GTSDescriptor), lambda pkt: pkt.gts_spec_desccount > 0),
        ConditionalField(PacketField('gts_desc2', GTSDescriptor(), GTSDescriptor), lambda pkt: pkt.gts_spec_desccount > 1),
        ConditionalField(PacketField('gts_desc3', GTSDescriptor(), GTSDescriptor), lambda pkt: pkt.gts_spec_desccount > 2),
        ConditionalField(PacketField('gts_desc4', GTSDescriptor(), GTSDescriptor), lambda pkt: pkt.gts_spec_desccount > 3),
        ConditionalField(PacketField('gts_desc5', GTSDescriptor(), GTSDescriptor), lambda pkt: pkt.gts_spec_desccount > 4),
        ConditionalField(PacketField('gts_desc6', GTSDescriptor(), GTSDescriptor), lambda pkt: pkt.gts_spec_desccount > 5),
        ConditionalField(PacketField('gts_desc7', GTSDescriptor(), GTSDescriptor), lambda pkt: pkt.gts_spec_desccount > 6),

    ]

    def guess_payload_class(self, payload):
        return Padding


class PendingAddressFields(Packet):

    name = "Pending Address Fields"

    fields_desc = [

        #  Pending Address Specification (1 byte)        
        BitField("pa_num_short", 0, 3), #number of short addresses pending
        BitField("pa_reserved_1", 0, 1),
        BitField("pa_num_long", 0, 3), #number of long addresses pending
        BitField("pa_reserved_2", 0, 1),

        #  Address List (var length)
        # Short addresses
        ConditionalField(dot15d4AddressField("short_addr1", 0, adjust=lambda pkt, x: 2), lambda pkt: pkt.pa_num_short > 0),
        ConditionalField(dot15d4AddressField("short_addr2", 0, adjust=lambda pkt, x: 2), lambda pkt: pkt.pa_num_short > 1),
        ConditionalField(dot15d4AddressField("short_addr3", 0, adjust=lambda pkt, x: 2), lambda pkt: pkt.pa_num_short > 2),
        ConditionalField(dot15d4AddressField("short_addr4", 0, adjust=lambda pkt, x: 2), lambda pkt: pkt.pa_num_short > 3),
        ConditionalField(dot15d4AddressField("short_addr5", 0, adjust=lambda pkt, x: 2), lambda pkt: pkt.pa_num_short > 4),
        ConditionalField(dot15d4AddressField("short_addr6", 0, adjust=lambda pkt, x: 2), lambda pkt: pkt.pa_num_short > 5),
        ConditionalField(dot15d4AddressField("short_addr7", 0, adjust=lambda pkt, x: 2), lambda pkt: pkt.pa_num_short > 6),

        # Long addresses
        ConditionalField(dot15d4AddressField("long_addr1", 0, adjust=lambda pkt, x: 8), lambda pkt: pkt.pa_num_long > 0),
        ConditionalField(dot15d4AddressField("long_addr2", 0, adjust=lambda pkt, x: 8), lambda pkt: pkt.pa_num_long > 1),
        ConditionalField(dot15d4AddressField("long_addr3", 0, adjust=lambda pkt, x: 8), lambda pkt: pkt.pa_num_long > 2),
        ConditionalField(dot15d4AddressField("long_addr4", 0, adjust=lambda pkt, x: 8), lambda pkt: pkt.pa_num_long > 3),
        ConditionalField(dot15d4AddressField("long_addr5", 0, adjust=lambda pkt, x: 8), lambda pkt: pkt.pa_num_long > 4),
        ConditionalField(dot15d4AddressField("long_addr6", 0, adjust=lambda pkt, x: 8), lambda pkt: pkt.pa_num_long > 5),
        ConditionalField(dot15d4AddressField("long_addr7", 0, adjust=lambda pkt, x: 8), lambda pkt: pkt.pa_num_long > 6),
        
        
        ]

    def guess_payload_class(self, payload):
        return Padding

class Dot15d4Beacon(_CommonMAC):

    name = "802.15.4 Beacon"
    fields_desc = [

        #2006
        MyConditionalField(PacketField('aux_sec_header', Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),\
                         lambda pkt: (pkt.underlayer != None) and pkt.underlayer.fcf_security and pkt.underlayer.fcf_framever),

        # Superframe spec field:
        BitField("sf_sforder", 15, 4),
        BitField("sf_beaconorder", 15, 4),
        BitEnumField("sf_assocpermit", 0, 1, [False, True]),
        BitEnumField("sf_pancoord", 0, 1, [False, True]),
        BitField("sf_reserved", 0, 1),
        BitEnumField("sf_battlifeextend", 0, 1, [False, True]),
        BitField("sf_finalcapslot", 15, 4),

        #GTS fields
        PacketField('gts_fields', GTSFields(), GTSFields),

        #Pending Address fields
        PacketField('pending_addr_fields', PendingAddressFields(), PendingAddressFields),

        #2003
        MyConditionalField(PacketField('aux_sec_header_2003', Dot15d4AuxSecurityHeader2003(), Dot15d4AuxSecurityHeader2003),\
                         lambda pkt: (pkt.underlayer != None) and pkt.underlayer.fcf_security and not pkt.underlayer.fcf_framever),

    ]

    def guess_payload_class(self, payload):

        if isinstance(self.underlayer, Dot15d4) and self.underlayer.fcf_security:
            
            if conf.dot15d4auto_unsecure and self.security_material_available():
                # If there, it means that frame has been unsecured
                return BeaconUnsecuredPayload

            else:
                return BeaconSecuredPayload

        else:
            return BeaconPayload

    def get_secured_class(self):

        return BeaconSecuredPayload

    def get_unsecured_class(self, pay):

        return BeaconUnsecuredPayload
    

class BeaconPayload(Raw):
    name = '802.15.4 Beacon payload'


# BEACON RELATED MATERIAL ---


# COMMAND  RELATED MATERIAL +++

class Dot15d4Cmd(_CommonMAC):
    name = "802.15.4 Command"

    fields_desc = [

        #2006
        MyConditionalField(PacketField('aux_sec_header', Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),\
                         lambda pkt: (pkt.underlayer != None) and pkt.underlayer.fcf_security and pkt.underlayer.fcf_framever),

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

        #2003
        MyConditionalField(PacketField('aux_sec_header_2003', Dot15d4AuxSecurityHeader2003(), Dot15d4AuxSecurityHeader2003),\
                         lambda pkt: (pkt.underlayer != None) and pkt.underlayer.fcf_security and not pkt.underlayer.fcf_framever),

    ]

    
    # command frame payloads are complete: DataReq, PANIDConflictNotify, OrphanNotify, BeaconReq don't have any payload
    # Although BeaconReq can have an optional ZigBee Beacon payload (implemented in ZigBeeBeacon)
    def guess_payload_class(self, payload):

        if isinstance(self.underlayer, Dot15d4) and self.underlayer.fcf_security:
            
            if conf.dot15d4auto_unsecure and self.security_material_available():
                # If there, it means that frame has been unsecured

                if self.cmd_id == 1:
                    return Dot15d4CmdAssocReqUnsecured
                elif self.cmd_id == 2:
                    return Dot15d4CmdAssocRespUnsecured
                elif self.cmd_id == 3:
                    return Dot15d4CmdDisassociationUnsecured
                elif self.cmd_id == 8:
                    return Dot15d4CmdCoordRealignUnsecured
                elif self.cmd_id == 9:
                    return Dot15d4CmdGTSReqUnsecured
                else:
                    return Raw

            else:

                if self.cmd_id == 1:
                    return Dot15d4CmdAssocReqSecured
                elif self.cmd_id == 2:
                    return Dot15d4CmdAssocRespSecured
                elif self.cmd_id == 3:
                    return Dot15d4CmdDisassociationSecured
                elif self.cmd_id == 8:
                    return Dot15d4CmdCoordRealignSecured
                elif self.cmd_id == 9:
                    return Dot15d4CmdGTSReqSecured
                else:
                    return Raw

        
        else:

            if self.cmd_id == 1:
                return Dot15d4CmdAssocReq
            elif self.cmd_id == 2:
                return Dot15d4CmdAssocResp
            elif self.cmd_id == 3:
                return Dot15d4CmdDisassociation
            elif self.cmd_id == 8:
                return Dot15d4CmdCoordRealign
            elif self.cmd_id == 9:
                return Dot15d4CmdGTSReq
            else:
                return Raw

            
    def get_secured_class(self):

        if self.cmd_id == 1:
            return Dot15d4CmdAssocReqSecured
        elif self.cmd_id == 2:
            return Dot15d4CmdAssocRespSecured
        elif self.cmd_id == 3:
            return Dot15d4CmdDisassociationSecured
        elif self.cmd_id == 8:
            return Dot15d4CmdCoordRealignSecured
        elif self.cmd_id == 9:
            return Dot15d4CmdGTSReqSecured
        else:
            return Raw

    def get_unsecured_class(self, pay):

        if self.cmd_id == 1:
            return Dot15d4CmdAssocReqUnsecured
        elif self.cmd_id == 2:
            return Dot15d4CmdAssocRespUnsecured
        elif self.cmd_id == 3:
            return Dot15d4CmdDisassociationUnsecured
        elif self.cmd_id == 8:
            return Dot15d4CmdCoordRealignUnsecured
        elif self.cmd_id == 9:
            return Dot15d4CmdGTSReqUnsecured
        else:
            return Raw
        

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
    
# COMMAND  RELATED MATERIAL ---



# Handling SECURED MAC payload '''

class SecuredPayload(Packet):
    pass

class DataSecuredPayload(SecuredPayload):
    name = '802.15.4 Secured Data Payload ' 
    fields_desc = [Raw]
    
class BeaconSecuredPayload(SecuredPayload):
    name = '802.15.4 Secured Beacon Payload '
    fields_desc = [Raw]
    
class Dot15d4CmdAssocReqSecured(Dot15d4CmdAssocReq, SecuredPayload):
    name = '802.15.4 Secured Association Request '
    fields_desc = [Raw]
    
class Dot15d4CmdAssocRespSecured(Dot15d4CmdAssocResp, SecuredPayload):
    name = '802.15.4 Secured Association Response '
    fields_desc = [Raw]

class Dot15d4CmdDisassociationSecured(Dot15d4CmdDisassociation, SecuredPayload):
    name = '802.15.4 Secured Disassociation Notification '
    fields_desc = [Raw]
    
class Dot15d4CmdCoordRealignSecured(Dot15d4CmdCoordRealign, SecuredPayload):
    name = '802.15.4 Secured Coordinator Realignment '
    fields_desc = [Raw]
    
class Dot15d4CmdGTSReqSecured(Dot15d4CmdGTSReq, SecuredPayload):
    name = '802.15.4 Secured GTS Request '
    fields_desc = [Raw]

    
# Handling UNSECURED MAC payload
    
class DataUnsecuredPayload(DataPayload):
    name = '802.15.4 Unsecured Data Payload' 
    
class BeaconUnsecuredPayload(BeaconPayload):
    name = '802.15.4 Unsecured Beacon Payload'

class Dot15d4CmdAssocReqUnsecured(Dot15d4CmdAssocReq):
    name = '802.15.4 Unsecured Association Request'

class Dot15d4CmdAssocRespUnsecured(Dot15d4CmdAssocResp):
    name = '802.15.4 Unsecured Association Response'

class Dot15d4CmdDisassociationUnsecured(Dot15d4CmdDisassociation):
    name = '802.15.4 Unsecured Disassociation Notification'

class Dot15d4CmdCoordRealignUnsecured(Dot15d4CmdCoordRealign):
    name = '802.15.4 Unsecured Coordinator Realignment'

class Dot15d4CmdGTSReqUnsecured(Dot15d4CmdGTSReq):
    name = '802.15.4 Unsecured GTS Request'


        
### Utility Functions ###
def util_srcpanid_present(pkt):
    '''A source PAN ID is included if and only if both src addr mode != 0 and PAN ID Compression in FCF == 0'''
    if (pkt.getfieldval("fcf_srcaddrmode") != 0) and (pkt.getfieldval("fcf_panidcompress") == 0):
        return True
    else:
        return False


def getAESKey(key=""):
    # Key
    if key == "":
        try:
            key = conf.dot15d4key
        except Exception, e:
            return None

    if key == '':
        return None
    
    if len(key) != 32 and key != "":
        warning("The length of the key must do 16 bytes")
        return None

    return key

def getSec2003Config(securitysuite=None):

    if securitysuite == None:
        try:
            securitysuite = conf.dot15d4securitysuite
        except Exception, e:
            pass

    if securitysuite > 7:
        warning("The security suite must be an interger between 0 and 7")
        securitysuite=None

    return securitysuite


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


### Bindings ###
bind_layers( Dot15d4, Dot15d4Beacon, fcf_frametype=0)
bind_layers( Dot15d4, Dot15d4Data, fcf_frametype=1)
bind_layers( Dot15d4, Dot15d4Ack,  fcf_frametype=2)
bind_layers( Dot15d4, Dot15d4Cmd,  fcf_frametype=3)
bind_layers( Dot15d4FCS, Dot15d4Beacon, fcf_frametype=0)
bind_layers( Dot15d4FCS, Dot15d4Data, fcf_frametype=1)
bind_layers( Dot15d4FCS, Dot15d4Ack,  fcf_frametype=2)
bind_layers( Dot15d4FCS, Dot15d4Cmd,  fcf_frametype=3)

bind_layers( Dot15d4Cmd, Dot15d4CmdAssocReq, cmd_id=1)
bind_layers( Dot15d4Cmd, Dot15d4CmdAssocResp, cmd_id=2)
bind_layers( Dot15d4Cmd, Dot15d4CmdDisassociation, cmd_id=3)
bind_layers( Dot15d4Cmd, Dot15d4CmdCoordRealign, cmd_id=8)
bind_layers( Dot15d4Cmd, Dot15d4CmdGTSReq, cmd_id=9)

### DLT Types ###
conf.l2types.register(195, Dot15d4FCS)
conf.l2types.register(230, Dot15d4)

### dot15d4_database related material ###

#Use when security is to be applied but srcaddrmode is short
conf.dot15d4_use_default_address=0
conf.dot15d4_default_extended_address=None

#Use for maleability encryption/decryption
conf.dot15d4_use_maleability=0
conf.dot15d4_keystreams=None

# To load database, use function load_dot15d4_database(path to json)
conf.dot15d4_database=None
conf.dot15d4use_database = 0

conf.dot15d4auto_secure=0
conf.dot15d4auto_unsecure=0

def load_dot15d4_keystreams(path):

    try:

        with open(path, 'r') as _ks:
            conf.dot15d4_keystreams = json.loads(_ks.read())
            
        return True

    except:

        warning('Could not load dot15d4 keystreams, check out the path you provide (wrong location?/wrong rights?)')
        
        return False


def load_dot15d4_database(path):

    try:

        with open(path, 'r') as _db:
            conf.dot15d4_database = json.loads(_db.read())

        return True

    except:

        warning('Could not load database, check out the path you provide (wrong location?/wrong rights?)')
        
        return False

def dot15d4_db_getids(js, pkt):

    if pkt.underlayer.fcf_srcaddrmode == 2:

        srcaddr16 = pkt.underlayer.src_addr
        srcaddr64 = None
        
    elif pkt.underlayer.fcf_srcaddrmode == 3:

        srcaddr64 = pkt.underlayer.src_addr
        srcaddr16 = None

    else:

        srcaddr16 = srcaddr64 = None
            
    if pkt.underlayer.fcf_destaddrmode == 2:

        destaddr16 = pkt.underlayer.dest_addr
        destaddr64 = None
        
    elif pkt.underlayer.fcf_destaddrmode == 3:

        destaddr64 = pkt.underlayer.dest_addr
        destaddr16 = None
        
    else:
        destaddr16 = destaddr64 = None
            
                
    # Getting panids (src and dest)
    if pkt.underlayer.fcf_panidcompress:
        src_panid = dest_panid = pkt.underlayer.dest_panid
    else:
        src_panid = pkt.underlayer.src_panid
        dest_panid = pkt.underlayer.dest_panid
            
        
    src_id, dest_id = None, None

    # Are source known in loaded database
    for device in js['Devices']:
        
        if device.has_key('addr64') and device.has_key('panid'):
            if device['addr64'] == srcaddr64 and device['panid'] == src_panid :
                src_id = device['id']
                break
            
        if device.has_key('addr16') and device.has_key('panid'):
            if device['addr16'] == srcaddr16 and device['panid'] == src_panid :
                src_id = device['id']
                break

        if device.has_key('pan_coord') and device.has_key('panid'):
            if device['panid'] == src_panid and not srcaddr16 and not srcaddr64:
                src_id = device['id']
                break


    # Are destination known in loaded database
    for device in js['Devices']:

        if device.has_key('addr64') and device.has_key('panid'):
            if device['addr64'] == destaddr64 and device['panid'] == dest_panid :
                dest_id = device['id']
                break

        if device.has_key('addr16'):
            if device['addr16'] == destaddr16 and device['panid'] == dest_panid :
                dest_id = device['id']
                break

        if device.has_key('pan_coord') and device.has_key('panid'):
            if device['panid'] == dest_panid and not destaddr16 and not destaddr64:
                dest_id = device['id']
                break
    
    return src_id, dest_id



def dot15d4_db_security_found(js, pkt, src_id, dest_id):

    for recipient in js['Devices'][src_id]['Recipients']:

        if recipient['id'] == dest_id:
            # Destination has been registred has a recipient of Source
                    
            for transmission in recipient['Transmissions']:
                        
                if transmission['frametype'] == pkt.underlayer.fcf_frametype and transmission['frame_version'] == pkt.underlayer.fcf_framever:

                    if transmission['frametype'] == 3: # Cmd
                            
                        if transmission['framesubtype'] == pkt.cmd_id:
                            # The transmission we were looking for

                            if transmission.has_key('Security') and transmission['Security']['security_found'] == True:
                                return True
                            else:
                                return False

                    else:
                        # The transmission we were looking for
                        if transmission.has_key('Security') and transmission['Security']['security_found'] == True:
                            return True                                
                        else:
                            return False

    return False



def dot15d4_db_security_material_available(pkt, js):

    src_id, dest_id = dot15d4_db_getids(js, pkt)
        
    # Are one or both devices unknown ?
    if src_id == None or dest_id == None:
        return False

    return dot15d4_db_security_found(js, pkt, src_id, dest_id)

        

''' Return value: Tuple (key, srcaddr64, security_level, deviations_list)
or None '''

def dot15d4_db_get_security_material(pkt, js):

    src_id, dest_id = dot15d4_db_getids(js, pkt)

    if src_id == None or dest_id == None:
        return None

    return dot15d4_db_get_sec_conf(js, pkt, src_id, dest_id)


''' Used for sixlowpan only '''
def dot15d4_db_get_transmission_conf(_db, src_addr, dest_addr, src_panid, dest_panid):

    if _db != None:

        for device in _db['Devices']:

            if (device.get('addr16') == src_addr or device.get('addr64') == src_addr) and device.get('panid') == src_panid:

                for recipient in device['Recipients']:

                    if (_db['Devices'][recipient.get('id')].get('addr16') == dest_addr or _db['Devices'][recipient.get('id')].get('addr64') == src_addr):

                        if _db['Devices'][recipient.get('id')].get('panid') == dest_panid:

                            for transmission in recipient['Transmissions']:

                                if transmission.get('frametype') == 1:  # Data
                                    # We found transmission
                                    return transmission.get('security_enabled'), transmission.get('frame_version')

    return None, None
                            


''' Return value: Tuple (key, srcaddr64, security_level, deviations_list)
or None '''            
def dot15d4_db_get_sec_conf(js, pkt, src_id, dest_id):


    if src_id == None or dest_id == None:
        return None

    for recipient in js['Devices'][src_id]['Recipients']:

        if recipient['id'] == dest_id:
            # Destination has been registred has a recipient of Source
                    
            for transmission in recipient['Transmissions']:
                        
                if transmission['frametype'] == pkt.underlayer.fcf_frametype and transmission['frame_version'] == pkt.underlayer.fcf_framever:

                    if transmission['frametype'] == 3: # Cmd
                            
                        if transmission['framesubtype'] == pkt.cmd_id:
                            # The transmission we were looking for

                            if transmission.has_key('Security') and transmission['Security']['security_found'] == True:
                                return (transmission['Security']['key'], js['Devices'][src_id]['addr64'], transmission['Security']['security_policy'], transmission['Security'].get('deviations_list', {}))
                            else:
                                return None

                    else:
                        # The transmission we were looking for
                        if transmission.has_key('Security') and transmission['Security']['security_found'] == True:
                            return (transmission['Security']['key'], js['Devices'][src_id]['addr64'], transmission['Security']['security_policy'], transmission['Security'].get('deviations_list', {}))
                        else:
                            return None

    return None


def dot15d4_get_ndp_table(_db):

    ndp_table = {}
    
    if _db != None:

        for device in _db['Devices']:

            for recipient in device['Recipients']:

                for transmission in recipient['Transmissions']:

                    if transmission.has_key('Sixlowpan'):
        
                        if device.has_key('panid'):

                            ndp_table[transmission['Sixlowpan']['src']] = { 'short' : device.get('addr16'),
                                                                            'long' : device.get('addr64'),
                                                                            'panid' : device.get('panid')}
                            
                        '''if _db['Devices'][recipient['id']].has_key('panid'):
                            
                            ndp_table[transmission['Sixlowpan']['dst']] = { 'short' : _db['Devices'][recipient['id']].get('addr16'),
                                                                            'long' : _db['Devices'][recipient['id']].get('addr64'),
                                                                            'panid' : _db['Devices'][recipient['id']].get('panid')}'''

    return ndp_table

                                                                       

def dot15d4_db_ll_destiny_from_ipv6(_db, src_ipv6, dest_ipv6):

    if _db != None:

        for device in _db['Devices']:

            for recipient in device['Recipients']:

                for transmission in recipient['Transmissions']:

                    if transmission.has_key('Sixlowpan'):

                        if transmission['Sixlowpan']['src'] == src_ipv6 and transmission['Sixlowpan']['dst'] == dest_ipv6:

                            return _db['Devices'][recipient['id']].get('addr16', None), _db['Devices'][recipient['id']].get('addr64', None), _db['Devices'][recipient['id']].get('panid', None)

    return None , None, None


    


    



    
