#!/usr/bin/python2

# Copyright (C) Airbus Defence and Space
# Authors: Adam Reziouk, Jean-Michel Huguet, Jonathan-Christofer Demay

## This program is free software; you can redistribute it and/or modify it 
## under the terms of the GNU General Public License version 3 as
## published by the Free Software Foundation.
##
## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details

from scapy.all import *
import fcntl
import os
import sys
import struct
import subprocess
import time 
from socket import *
from select import select
from scapy.config import conf
import scapy.modules.gnuradio

from SixLowPANFragBuf import sixlowpan_frag_buf as _6buf

conf.use_dot15d4_database = 1

# Some constants used to ioctl the device file.
TUNSETIFF = 0x400454ca
TUNSETOWNER = TUNSETIFF + 2
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

# Open TUN device file.
tun = open('/dev/net/tun', 'r+b')

# Tell it we want a TUN device named tun0.
ifr = struct.pack('16sH', 'tun0', IFF_TUN | IFF_NO_PI)
fcntl.ioctl(tun, TUNSETIFF, ifr)

os.system("ifconfig tun0 up")

os.system("ifconfig tun0 inet6 add fe80::0213:a200:4081:b470/64")  # default IPv6 address


# This is a hand-made NDP table. Keys of NDP_table correponds to IPv6 addresses.
# Value is a dictionnary of either a source or a long 802.15.4 address or both of them.
# Example : 
#
# NDP_table = {
#     "fe80::1" : { "long" : 0x44444444444444444, "short" : 0x5454},
#     "fe80::5" : {"short" : 0x4777}
#     }

NDP_Table = {}

load_module('gnuradio')
conf.L2listen=GnuradioSocket_in
conf.L3socket=GnuradioSocket_out

switch_radio_protocol("Zigbee")
print "Launching Gnuradio in background..."
time.sleep(10)
gnuradio_set_vars(Channel=12)



class A(Automaton):

    def parse_args(self, panid=0xabcd, ieee802_16_addr = 0x1500, ieee802_64_addr = 0x0013a2004081b470, spoof_ipv6_addr = "", ndp_table={}, **kargs):
        Automaton.parse_args(self, **kargs)
        self.buffers = {}

        self.waiting_ndp_advertissment = {}  # Here we strore all the IPv6 packet we couldn't sent because of missing MAC addr.  
        
        self.datagram_tag = 0  # Initilaisation of datagram_tag (only used when sending fragmented frames)

        self.spoof_ipv6_addr = spoof_ipv6_addr
        self.my_16_802_addr = ieee802_16_addr
        self.my_64_802_addr = ieee802_64_addr

        self.my_panid = panid # Just to debug, must be modified

        if isinstance(ndp_table, dict):
            self.ndp_table = ndp_table

        # update ndp_table from conf with something like : self.ndp_table = dict(self.ndp_table, **conf.ndp_table) (USEFULL WHEN USING SCANNER)

        #self.my_ipv6 = "fe80::250:bfff:fed7:5a8b" 
        self.my_ipv6 = 'fe80::0213:a200:4081:b470'  # default ipv6 address of the router

        # When we want to spoof
        if self.ndp_table.get(spoof_ipv6_addr, {}) != {}:
            self.my_ipv6 = spoof_ipv6_addr
            
        p = Dot15d4FCS(fcf_srcaddrmode=2) / Dot15d4Data(src_addr=self.my_16_802_addr) / Raw("ujhjhjhgjkhgghkjghkjhgkjhgkjghkjgkjgkjgkjhgkjghkjhgkjgkjhgkjghkjgkjgkjgkjhgkjhg")
        send(p)  # dummy packet


    def master_filter(self, pkt):

        if pkt.proto == 0:
            print 'Invalid packet'  # bad FCS
            return False


        if Dot15d4FCS in pkt:  # Problem with usrp : we sniff what we are sending! Check if src addr is ours! If yes drop

            if pkt.fcf_srcaddrmode == 2:
                if pkt.src_addr == self.my_16_802_addr:
                    return False
            elif pkt.fcf_srcaddrmode == 3:
                if pkt.src_addr == self.my_64_802_addr:
                    return False
        else:
            return False

        if SixLoWPAN in pkt:

            if LoWPANMesh in pkt and (pkt[LoWPANMesh]._destinyAddr != self.my_16_802_addr and pkt[LoWPANMesh]._destinyAddr != self.my_64_802_addr):
                # Packet is not for us ! Our tool is not supposed to route sixlowpan packet from a device to another
                return False
            return True

    @ATMT.state(initial=1)
    def begin(self):
        pass

    # Do we get a 6LowPAN packet
    @ATMT.receive_condition(begin, prio=1)
    def receive_condition(self,pkt):
        raise self.begin().action_parameters(pkt)

    @ATMT.action(receive_condition)
    def handle_6lowpan_packet(self, pkt):

        if Dot15d4AuxSecurityHeader2003 in pkt:

            p = pkt[Dot15d4FCS].copy()
            
            _6l = p[Dot15d4AuxSecurityHeader2003].payload

            p[Dot15d4Data].payload = _6l

            p.fcf_security = 0

            p = Dot15d4FCS(str(p))

            pkt = p

        if Dot15d4AuxSecurityHeader in pkt:

            p = pkt[Dot15d4FCS].copy()
            
            _6l = p[Dot15d4AuxSecurityHeader].payload

            p[Dot15d4Data].payload = _6l

            p.fcf_security = 0

            p = Dot15d4FCS(str(p))

            pkt = p

        if LoWPANMesh in pkt:
            # At this point, we sure that the packet is for us! See the master_filter function
            pkt = self.remove_lowpan_mesh_header(pkt)

        if LoWPANFragmentationFirst in pkt or LoWPANFragmentationSubsequent in pkt:

            src = pkt.src_addr # 802.15.4 address
            dst = pkt.dest_addr # 802.15.4 address
            tag = pkt[SixLoWPAN].payload.datagramTag
            name_key = str(src) + '_' + str(dst) + '_' + str(tag)
            
            if LoWPANFragmentationFirst in pkt:

                print "Received Fragmentation First packet"
                # Add a key entry in the buffer dictionnary
                self.buffers[name_key] = _6buf(pkt)
                return # Nothing else to do for this packet

            else:

                print "Received Fragmentation Subsequent packet"
                
                # Subsequent Fragment: add it in the buffer 
                try:
                    self.buffers[name_key] << pkt
                    return # Nothing else to do for this packet
                    
                except _6buf.SixlowpanBufferFull:

                    # All the fragments has been received
                    plist = PacketList(self.buffers[name_key].plist, 'Fragmented')  # Get the packet list
                    self.buffers.pop(name_key)  # remove buffer from list
                
                    # Lets defragment the packet
                    pkt = self.lowpandefragment(plist)


        if LoWPANUncompressedIPv6 in pkt:

            ipv6_pkt = pkt[LoWPANUncompressedIPv6].payload  # ipv6 header + ipv6 payload

            if ICMPv6ND_NA in ipv6_pkt:  # Neighbor Advertissment
                    
                if self.handle_ndp_advertissment(ipv6_pkt, pkt):
                    # pkt was for us
                    raise self.begin()
                
            self.oi.my_events.write(bytes(ipv6_pkt)) # Forward packet to tun/tap

            raise self.begin()

        elif LoWPAN_IPHC in pkt:
            
            ipv6_hdr_str = self.build_ipv6_header_from_iphc(pkt)  # return ipv6 header in string format

            ipv6_pkt = self.generate_ipv6(ipv6_hdr_str, pkt)

            if ipv6_pkt == None:
                raise self.begin()
                
            if ICMPv6ND_NA in ipv6_pkt:
                if self.handle_ndp_advertissment(ipv6_pkt, pkt):
                    raise self.begin()

            self.oi.my_events.write(bytes(ipv6_pkt)) # Forward packet to tun/tap
            
            raise self.begin()

        else:
            
            pkt.show()
            print "Packet RF dropped"
            raise self.begin()
            

    # Do we get a IPv6 packet
    @ATMT.ioevent(begin, name="my_events", prio=0)
    def test_ioevent(self, fd):

        # Note: for the moment, we do not handle the Mesh in emission
        obj = fd.recv()
        ipv6_pkt = IPv6(obj)

        # Need to fix this : When running this script, some ipv6 packet are send by the computer
        if ipv6_pkt[IPv6].dst == "ff02::fb" or ipv6_pkt[IPv6].dst == "ff02::16":
            print "MDNS : packet dropped"
            raise self.begin()

        # Need to fix this : When running this script, some ipv6 packet are send by the computer
        if ICMPv6ND_RS in ipv6_pkt:
            print "Router sollicitation : packet dropped"  
            raise self.begin()

        self.handle_ipv6_pkt(ipv6_pkt)
        
        raise self.begin()


    @ATMT.state(final=1)
    def end(self):
        return


    def handle_ndp_advertissment(self, ipv6_pkt, pkt):

        ipv6_src = ipv6_pkt[IPv6].src

        # Maybe a response to a Neigbourg solicitation 
        if str(ipv6_src) in self.waiting_ndp_advertissment:
                    
            # Update the ndp table
            self.ndp_table[str(ipv6_src)] = (lambda x,y: x==2 and {"short" : y} or {"long":y} )(pkt.fcf_srcaddrmode, pkt.src_addr)
                    
            # Retrieve the waiting pkt
            ipv6_pkt = self.waiting_ndp_advertissment.pop(str(ipv6_src))

            time.sleep(0.2)

            # Handle ipv6 packet as usual
            self.handle_ipv6_pkt(ipv6_pkt)

            return True

        return False  # pkt is not for us! Maybe update ndp table even if ndp advertissment is not for us
            

    def handle_ipv6_pkt(self, ipv6_pkt):

        ipv6_dst = ipv6_pkt[IPv6].dst

        # Check the ndp table to get the mac adresses of our destination
        mac_dest_addresses = self.ndp_table.get(str(ipv6_dst), {})
        
        if mac_dest_addresses == {}:
            # We do not know the mac adress of the device we want to communicate with

            # Store the packet to send until we got the information we need! 
            self.waiting_ndp_advertissment[str(ipv6_dst)] = ipv6_pkt
            
            # Forge an NDP request
            # Note: the source adress may be compressed, but the destiny address won't because the mac address has been set
            # to broadcast address : 0xffff 
            #            ndp_ns = Dot15d4FCS(fcf_destaddrmode=2, fcf_srcaddrmode= self.my_16_802_addr and 2 or 3) / \
                #                     Dot15d4Data(src_addr= self.my_16_802_addr or self.my_64_802_addr,\
                #                                 src_panid=self.my_panid, dest_addr=0xffff, dest_panid=0xaaaa) /\
                #                     SixLoWPAN() / LoWPAN_IPHC(nextHeader=58, sourceAddr=self.my_ipv6, destinyAddr=ipv6_dst) /\
                #                     ICMPv6ND_NS(tgt=ipv6_dst) / ICMPv6NDOptSrcLLAddr(lladdr= "11:11") #  self.my_64_802_addr)
            ndp_ns = Dot15d4FCS(fcf_destaddrmode=2, fcf_srcaddrmode= 3) / Dot15d4Data(src_addr= self.my_64_802_addr,src_panid=self.my_panid, dest_addr=0xffff, dest_panid=0xffff)/ SixLoWPAN() / LoWPAN_IPHC(nextHeader=58, sourceAddr=self.my_ipv6, destinyAddr=ipv6_dst)/ICMPv6ND_NS(tgt=ipv6_dst) / ICMPv6NDOptSrcLLAddr(lladdr= "00:11:22:33:44:55:66:77") #  self.my_64_802_addr)
                        
            datagram_size = ipv6_pkt.plen + 40 # 40 is the length of the uncompressed ipv6 header

            self.send_pkt(ndp_ns, datagram_size)

        else:
                        
            mac_short_dest = mac_dest_addresses.get("short", None)
            mac_long_dest = mac_dest_addresses.get("long", None)                

            # Forge the link-layer packet            

            dot15d4 = Dot15d4FCS(fcf_security=1, fcf_srcaddrmode= 3, fcf_destaddrmode=2,\
                                fcf_panidcompress=1) / Dot15d4Data(src_addr=self.my_64_802_addr,\
                                                                   dest_addr=0xffff, dest_panid=self.my_panid) / Dot15d4AuxSecurityHeader2003(sec_framecounter=0xaaaaa, sec_keyseqcounter=0)
            '''

            dot15d4 = Dot15d4FCS(fcf_srcaddrmode= 3, fcf_destaddrmode= 2,\
                                fcf_panidcompress=1) / Dot15d4Data(src_addr=self.my_64_802_addr,\
                                dest_addr=0xffff, src_panid=self.my_panid)
            '''

            datagram_size = ipv6_pkt.plen + 40 # 40 is the length of the uncompressed ipv6 header
            
            pkt = self.forge_6lowpan_pkt(dot15d4, ipv6_pkt)

            self.send_pkt(pkt, datagram_size)


    def send_pkt(self, pkt, datagram_size):
        
        # Fragment it if necessary. If not the return value is a list of one element (pkt)
        plist = self.lowpanfragment(pkt, self.hdr6_len, self.uncomp_hdr_len, datagram_size, self.datagram_tag)

        wrpcap("fragmentation.pcap", plist)

        frag = len(plist) > 1 and True or False

        # Then send
        for p in plist:
            self.send(p)
            if frag: # Fragmented packet
                print "Sending fragment %d of packet" % plist.index(p)
                time.sleep(0.2)
            else:
                print "Sending unfragmented packet"

        if frag:
            self.datagram_tag += 1  # Increment datagram_tag 


    def forge_6lowpan_pkt(self, llpkt, ipv6_pkt):


        self.hdr6_len = 0 # Size of 6LoWPAN headers 
        self.uncomp_hdr_len = 0 # Size of headers (before compression) that have been compressed (IPv6 and/or UDP)

        ttl_values = {
            '1' : 1,
            '64' : 2,
            '255' : 3
        }
        

        # Prepare LoWPAN_IPHC header # 

        # Trafic class : ECN (2 bits) + DSCP (6 bits)
        tc = ipv6_pkt.tc
        ecn = tc >> 6 
        dscp = tc & 0x3F

        # Flowlabel
        fl = ipv6_pkt.fl
        
        # Fl and tc compression
        if fl == 0:
            # flowlabel can be elided
            tf = tc and 0b10 or 0b11  # if trafic class is 0 elide all 
        else:
            # flowlabel cannot be elided
            tf = dscp and 0b00 or 0b01  # if dscp is 0 elide it

        # TTL (Hop Limit)
        ttl = ipv6_pkt.hlim
        hlim = ttl_values.get(str(ttl), 0)  # if hlim is not in ttl_values, it will be carried inline

        # Addressing
        srcip = ipv6_pkt.src
        dstip = ipv6_pkt.dst

        #Next Header
        
        nh = UDP in ipv6_pkt
        
        nextHeader=0 
        
        if not nh:
            
            if TCP in ipv6_pkt:
                nextHeader = 6
            else:
                nextHeader = 58

        
        # 2/ Forge packet headers.
        pkt = llpkt / SixLoWPAN() / LoWPAN_IPHC(tf=tf, nh=nh, hlim=hlim, tf_ecn=ecn, tf_dscp=dscp, tf_flowlabel=fl, hopLimit=ttl, nextHeader=nextHeader, sourceAddr=srcip, destinyAddr=dstip)

        self.uncomp_hdr_len = 40 # IPv6 len before compression
        
        if nh:
            
            self.uncomp_hdr_len += 8 # Add UDP header len before compression
            pkt = pkt / self.forge_6lowpan_udp(llpkt, ipv6_pkt)


        #pkt2 = pkt[Dot15d4FCS].copy() avant modif        
        #pkt2[Dot15d4Data].payload = None  avant modif

        pkt2 = pkt[Dot15d4FCS].copy()

        if Dot15d4AuxSecurityHeader2003 in pkt:
            pkt2[Dot15d4AuxSecurityHeader2003].payload = None
        
        elif Dot15d4AuxSecurityHeader in pkt:
            pkt2[Dot15d4AuxSecurityHeader].payload = None

        else:
            pkt2[Dot15d4Data].payload = None
        
        self.hdr6_len = len(pkt) - len(pkt2)

        # 3/ Add payload        
        if UDP in ipv6_pkt:
            udp_pay = ipv6_pkt[UDP].payload
            pkt = pkt / udp_pay
        else:
            pay = ipv6_pkt[IPv6].payload
            pkt = pkt / pay
        
        return pkt 


    def forge_6lowpan_udp(self, llpkt, ipv6_pkt):


        # 1/ Prepare LoWPAN_UDP header

        sport = ipv6_pkt[UDP].sport
        dport = ipv6_pkt[UDP].dport
        chksumformat = 0  # inline / We choose to carry the checksum inline
        
        # 2/ Forge packet. 
        pkt = LoWPAN_UDP(chksumformat=chksumformat, sport=sport, dport=dport)

        return pkt


    def remove_lowpan_mesh_header(self, pkt):

        # Update the 802.15.4 adressing information layer
        # Note : This information may be essential to decompress IPV6 header 
        pkt[Dot15d4FCS].fcf_srcaddrmode = (lambda p: p._v and 0x2 or 0x3)(pkt[LoWPANMesh])
        pkt[Dot15d4FCS].fcf_dstaddrmode = (lambda p: p._f and 0x2 or 0x3)(pkt[LoWPANMesh])
        pkt[Dot15d4FCS].src_addr = pkt[LoWPANMesh]._sourceAddr
        pkt[Dot15d4FCS].dest_addr = pkt[LoWPANMesh]._destinyAddr

        # Store the LoWPANMesh payload in string format
        raw = str(pkt[LoWPANMesh].payload)

        # Remove the SixLoWPAN layer from existing packet
        pkt[Dot15d4FCS].payload.payload = None 

        # Return new packet without the LoWPANMesh header
        return ( pkt / SixLoWPAN(raw) )  # A modifier car Dot15d4(HDR + raw)


    def lowpandefragment(self, plist):
        
        return lowpandefragment(plist)
        
    def lowpanfragment(self, pkt, hdr6_len, uncomp_hdr_len, datagram_size, datagram_tag):
        
        return lowpanfragment(pkt, hdr6_len, uncomp_hdr_len, datagram_size, datagram_tag)

        
    def build_ipv6_header_from_iphc(self, pkt):

        ttl_values = {
            '0' : pkt[LoWPAN_IPHC].hopLimit,  # Carried in-line
            '1' : 1,
            '2' : 64,
            '3' : 255
        }
        
        iphc = pkt[LoWPAN_IPHC]

        # Version
        ver = 0x6

        # Traffic class and Flow label
        tc = 0
        fl = 0 

        if iphc.tf == 0b00: # Everything is carried in-line
            tc = iphc.tf_ecn << 6 | iphc.tf_dscp
            fl = iphc.tf_flowlabel

        elif iphc.tf == 0b01: # DSCP is elided
            tc = iphc.tf_ecn << 6
            fl = iphc.tf_flowlabel

        elif iphc.tf == 0b10: # Flowlabel is elided 
            tc = iphc.tf_ecn << 6 | iphc.tf_dscp
            
        else:
            pass # Everything is elided

        # Payload Lenght
        plen = len(str(iphc.payload))

        # Next header
        if iphc.nh:
            nh = 17 # UDP
        else:
            nh = iphc.nextHeader # Normal cases : UDP/TCP/ICMPv6

        # Hop Limit
        ttl = ttl_values[str(iphc.hlim)]

        # Addressing information : they are automaticly uncompressed in dissection task
        src_ip = iphc.sourceAddr
        dst_ip = iphc.destinyAddr

        
        return str(IPv6(version=ver, tc=tc, fl=fl, plen=plen, nh=nh, hlim=ttl, src=src_ip, dst=dst_ip))

    def generate_ipv6(self, hdr, pkt):
        
        nh = {
            '6': TCP,
            '17' : UDP,
            '58' : ICMPv6Unknown,
        }

        if pkt.nh == 1:
            
            udp_hdr_str = self.build_udp_header_from_lowpanudp(pkt)
            
            if udp_hdr_str == None:
                return udp_hdr_str

            udp_payload = str(pkt[LoWPAN_UDP].payload)

            return IPv6(hdr + udp_hdr_str + udp_payload) # to test
        
        elif pkt.nextHeader in [6,17,58]:

            ipv6_payload =  str(pkt[LoWPAN_IPHC].payload)            
            return IPv6(hdr + ipv6_payload)

        else:

            print "unknown packet format"
            return None

    def build_udp_header_from_lowpanudp(self, pkt):
        
        if pkt[LoWPAN_UDP] != None:
            
            lowpan_udp = pkt[LoWPAN_UDP]

            # Ports
            sport = lowpan_udp.sport
            dport = lowpan_udp.dport
            
            # Len (udp header (8) + message(var) )
            length = 8 + len(str(lowpan_udp.payload))
            
            if lowpan_udp.chksumformat:
                chksum = 0
            else:
                chksum = lowpan_udp.chksum                
            
            return str(UDP(sport=sport, dport=dport, len=lenght, chksum=chksum))

        return None



ndp_table = { 'fe80::213:a200:40dc:580' : {"long" : 0x0013a20040dc0580} } 

a = A(external_fd={"my_events":tun}, ndp_table=ndp_table)
a.run()
