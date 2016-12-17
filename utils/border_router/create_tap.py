#!/usr/bin/python2
from scapy.all import *
import fcntl
import os
import sys
import struct
import subprocess
import time 

from select import select
from scapy.config import conf
import scapy.modules.gnuradio

from config import *
from ui import *

from socket import *
from scapy.layers.inet import *

from SixLowPANFragBuf import sixlowpan_frag_buf as _6buf


class BorderRouter(Automaton):

    def parse_args(self, my_ipv6, ndp_table={}, **kargs):

        Automaton.parse_args(self, **kargs)

        self.buffers = {}

        self.waiting_ndp_advertissment = {}  # Here we strore all the IPv6 packet we couldn't sent because of missing MAC addr.  
        
        self.datagram_tag = 0  # Initialisation of datagram_tag (only used when sending fragmented frames)

        self.routing_table = []  # Each entry is formated as a tuple (Source, Destination, Bridge)

        self.ndp_table = ndp_table

        self.my_ipv6 = my_ipv6

        self.my_16_802_addr = self.ndp_table[self.my_ipv6].get('short')
        self.my_64_802_addr = self.ndp_table[self.my_ipv6].get('long')
        self.my_panid = self.ndp_table[self.my_ipv6].get('panid')

        # Handling Dot15d4 layer conf
        conf.dot15d4key = DEFAULT_KEY
        conf.dot15d4auto_unsecure=1
        conf.dot15d4auto_secure=1
        conf.dot15d4_use_default_address=USE_DEFAULT_EXTENDED_SRC_ADDR
        conf.dot15d4_default_extended_address = DEFAULT_EXTENDED_SRC_ADDR
        
        # TO FIX A PROBLEM IN RELATION WITH GRC
        p = Dot15d4FCS(fcf_srcaddrmode=2, src_addr=0xffff) / Dot15d4Data() / Raw("ujhjhjhgjkhgghkjghkjhgkjhgkjghkjgkjgkjgkjhgkjghkjhgkjgkjhgkjghkjgkjgkjgkjhgkjhg")
        send(p)  # dummy packet


    def master_filter(self, pkt):

        if pkt.proto == 0:
            print 'Invalid packet'  # bad FCS
            return False


        if Dot15d4FCS in pkt and SixLoWPAN in pkt:

                
            if LoWPANMesh in pkt:
                
                # We dynamicaly infer information about mesh routing!
                found = 0
                
                if pkt._sourceAddr == pkt.src_addr:

                    for r in self.routing_table:
                        if r[0] == pkt.src_addr and r[1] == pkt._destinyAddr:
                            found = 1; break

                    if not found:
                        self.routing_table.append((pkt.src_addr, pkt._destinyAddr, pkt.dest_addr, pkt.fcf_destaddrmode))

                elif pkt._destinyAddr == pkt.dest_addr:

                    for r in self.routing_table:
                        if r[0] == pkt.dest_addr and r[1] == pkt._sourceAddr:
                            found = 1; break

                    if not found:
                        self.routing_table.append((pkt.dest_addr, pkt._sourceAddr, pkt.src_addr, pkt.fcf_srcaddrmode))


                if (pkt[LoWPANMesh]._destinyAddr != self.my_16_802_addr and pkt[LoWPANMesh]._destinyAddr != self.my_64_802_addr):
                    # Packet is not for us ! Our tool is not supposed to route sixlowpan packet from a device to another
                    return False

            # Problem with usrp : we sniff what we are sending! Check if src addr is ours! If yes drop
            if pkt.fcf_srcaddrmode == 2:
                if pkt.src_addr == self.my_16_802_addr:
                    return False
            elif pkt.fcf_srcaddrmode == 3:
                if pkt.src_addr == self.my_64_802_addr:
                    return False

            return True

        else:

            return False


    @ATMT.state(initial=1)
    def begin(self):
        pass

    # Do we get a 6LowPAN packet ?
    @ATMT.receive_condition(begin, prio=2)
    def receive_condition(self,pkt):
        raise self.begin().action_parameters(pkt)

    @ATMT.timeout(begin, 1)
    def ndp_timeout(self):

        list = []

        for k,v in self.waiting_ndp_advertissment.items():

            if v[1] == 0:

                # Timeout elapsed
                # Send packet in broadcast
                ipv6_pkt = v[0]
            
                # Handle ipv6 packet as usual
                self.handle_ipv6_pkt(ipv6_pkt)

                # Remove entry
                del self.waiting_ndp_advertissment[k]

            else:

                self.waiting_ndp_advertissment[k] = (v[0], v[1]-1)  # decrementing counter


        # Handling link layer fragmentation timeout
        for k,v in self.buffers.items():

            if v.timeout == 0:
                del self.buffers[k]
            else:
                self.buffers[k].timeout -= 1 
            
        raise self.begin()
    

    @ATMT.action(receive_condition)
    def handle_6lowpan_packet(self, pkt):

        if LoWPANFragmentationFirst in pkt or LoWPANFragmentationSubsequent in pkt:

            if LoWPANMesh in pkt:
                src = pkt._sourceAddr
                dst = pkt._destinyAddr
            else:
                src = pkt.src_addr
                dst = pkt.dest_addr

            tag = pkt.datagramTag
            size = pkt.datagramSize
            name_key = str(src) + '_' + str(dst) + '_' + str(tag) + '_' + str(size)
            
            if LoWPANFragmentationFirst in pkt:
                print "Received Fragmentation First packet from 0x%x" % pkt.src_addr
            else:
                print "Received Fragmentation Subsequent packet from 0x%x" % pkt.src_addr
            
            if self.buffers.has_key(name_key):
                # Feed buffer

                try:
                    self.buffers[name_key] << pkt
                    return

                except _6buf.SixlowpanBufferFull:

                    # All the fragments has been received
                    plist = PacketList(self.buffers[name_key].plist, 'Fragmented')  # Get the packet list
                    self.buffers.pop(name_key)

                    # Lets defragment the packet
                    pkt = self.lowpandefragment(plist)

            else:
                # Add a key entry in the buffer dictionnary
                self.buffers[name_key] = _6buf(pkt)

                return 

        else:

            print "Received Unfragmentation packet from 0x%x" % pkt.src_addr

        if LoWPANUncompressedIPv6 in pkt:

            ipv6_pkt = pkt[LoWPANUncompressedIPv6].payload  # ipv6 header + ipv6 payload

            if ICMPv6ND_NA in ipv6_pkt:  # Neighbor Advertissment
                    
                if self.handle_ndp_advertissment(ipv6_pkt, pkt):
                    # Response of our NDP request
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
            
            print "Packet RF dropped"
            raise self.begin()
            

    # Do we get a IPv6 packet
    @ATMT.ioevent(begin, name="my_events", prio=1)
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
        if ipv6_src in self.waiting_ndp_advertissment:

            # Update the ndp table
            if LoWPANMesh in pkt:

                self.ndp_table[ipv6_src] =  { 'short': ((pkt._v == 1) and pkt._sourceAddr) or None,
                                              'long': ((pkt._v == 0) and pkt._sourceAddr) or None,
                                              'panid' : pkt.fcf_panidcompress and pkt.dest_panid or pkt.src_panid }
            else:

                self.ndp_table[ipv6_src] =  { 'short': ((pkt.fcf_srcaddrmode == 2) and pkt.src_addr) or None,
                                              'long': ((pkt.fcf_srcaddrmode == 3) and pkt.src_addr) or None,
                                              'panid' : pkt.fcf_panidcompress and pkt.dest_panid or pkt.src_panid }

            # Retrieve the waiting pkt
            ipv6_pkt = self.waiting_ndp_advertissment.pop(ipv6_src)[0]

            # Handle ipv6 packet as usual
            self.handle_ipv6_pkt(ipv6_pkt)

            return True

        return False  # pkt is not for us! TODO : Maybe update ndp table even if ndp advertissment is not for us
            

    def handle_ipv6_pkt(self, ipv6_pkt):

        ipv6_dst = ipv6_pkt[IPv6].dst

        mac_short_dest, mac_long_dest, mac_panid_dest = None, None, None
        
        if conf.dot15d4_database != None:
            mac_short_dest, mac_long_dest, mac_panid_dest = dot15d4_db_ll_destiny_from_ipv6(conf.dot15d4_database, ipv6_pkt[IPv6].src, ipv6_pkt[IPv6].dst)
            
        if  mac_short_dest == None and  mac_long_dest == None:
            # Check the ndp table to get the mac adresses of our destination
            mac_dest_addresses = self.ndp_table.get(str(ipv6_dst), {})
        else:
            mac_dest_addresses = {'panid': mac_panid_dest, 'short':mac_short_dest, 'long':mac_long_dest}
            
        
        if mac_dest_addresses == {}:
            # We do not know the mac adress of the device we want to communicate with

            mac_panid_src = self.my_panid
            mac_short_src = self.my_16_802_addr
            mac_long_src = self.my_64_802_addr

            if mac_long_src == None or (self.waiting_ndp_advertissment.get(ipv6_dst) != None and self.waiting_ndp_advertissment[ipv6_dst][1] == 0):
                # Case 1: mac_long_src == None : Cannot send an NDP request because link-layer extended address is unknown
                # Case 2: self.waiting_ndp_advertissment[ipv6_dst][1] == 0 : Timeout elapsed while waiting for NDP Response 

                # Sending broadcast packet (dest_addr = 0xffff)
                # Setting broadcast dest_panid = 0xffff
                # Security not used

                if mac_short_src != None:
                    dot15d4 = Dot15d4FCS(fcf_srcaddrmode=2, src_addr=mac_short_src, fcf_destaddrmode=2, dest_addr=0xffff, src_panid = mac_panid_src, dest_panid = 0xffff) / Dot15d4Data()
                else:
                    dot15d4 = Dot15d4FCS(fcf_srcaddrmode=3, src_addr=mac_long_src, fcf_destaddrmode=2, dest_addr=0xffff, src_panid = mac_panid_src, dest_panid = 0xffff) / Dot15d4Data()

                datagram_size = ipv6_pkt.plen + 40 # 40 is the length of the uncompressed ipv6 header
            
                pkt = self.forge_6lowpan_pkt(dot15d4, ipv6_pkt)

                self.send_pkt(pkt, datagram_size)


            else:
                
                # Store the packet to send until we got the information we need! 
                self.waiting_ndp_advertissment[ipv6_dst] = (ipv6_pkt, 5) # 5 is a timeout counter 
            
                # Forge an NDP request
                # Note : Security is not used  for ndp request
                
                fcf_srcaddrmode, src_addr = self.which_src_addr_to_use(mac_short_src, mac_long_src, self.my_ipv6)

                ll_pkt = Dot15d4FCS(fcf_destaddrmode=2, fcf_srcaddrmode= fcf_srcaddrmode, src_addr= src_addr, src_panid=mac_panid_src, dest_addr=0xffff, dest_panid=0xffff) / Dot15d4Data()
                _6lp_pkt = SixLoWPAN() / LoWPAN_IPHC(nextHeader=58, sourceAddr=self.my_ipv6, destinyAddr=ipv6_dst)
                icmp_pkt = ICMPv6ND_NS(tgt=ipv6_dst) / ICMPv6NDOptSrcLLAddr(lladdr='aa:aa:aa:aa:aa:aa')#mac_long_src)

                ndp_head = ll_pkt / _6lp_pkt
                ndp_ns = ndp_head / icmp_pkt
                
                self.hdr6_len = len(ndp_head[SixLoWPAN])
                self.uncomp_hdr_len = 40 # IPv6 header
                
                datagram_size = ipv6_pkt.plen + 40 # 40 is the length of the uncompressed ipv6 header

                self.send_pkt(ndp_ns, datagram_size)


        else:

            # Getting link-layer information
            mac_panid_dest = mac_dest_addresses.get("panid")
            mac_short_dest = mac_dest_addresses.get("short")
            mac_long_dest = mac_dest_addresses.get("long")

            fcf_destaddrmode, dest_addr = self.which_dest_addr_to_use(mac_short_dest, mac_long_dest, ipv6_dst)

            mac_panid_src = self.my_panid
            mac_short_src = self.my_16_802_addr
            mac_long_src = self.my_64_802_addr

            fcf_srcaddrmode, src_addr = self.which_src_addr_to_use(mac_short_src, mac_long_src, self.my_ipv6)

            # check for mesh routing
            mesh = 0
            for entry in self.routing_table:
                if entry[0] == src_addr and entry[1] == dest_addr:
                    mesh = 1
                    self.mesh_destinyAddr = dest_addr
                    self.mesh_f = (fcf_destaddrmode == 2) and 1 or 0
                    dest_addr = entry[2]
                    fcf_destaddrmode = entry[3]
                
            security_enabled, frame_version, security_level = self.get_transmission_conf(src_addr, dest_addr, mac_panid_src, mac_panid_dest)

            # Forging link-layer packet
            dot15d4 = Dot15d4FCS(fcf_security=security_enabled, fcf_framever=frame_version) / Dot15d4Data()

            dot15d4.seqnum = 100
            dot15d4.fcf_srcaddrmode=fcf_srcaddrmode
            dot15d4.fcf_destaddrmode=fcf_destaddrmode
            dot15d4.fcf_panidcompress=0
            dot15d4.src_addr=src_addr
            dot15d4.dest_addr=dest_addr
            dot15d4.dest_panid=mac_panid_dest
            dot15d4.src_panid=mac_panid_src

            if security_enabled and frame_version:
                # 2006
                dot15d4.aux_sec_header.sec_sc_seclevel=security_level

            if security_enabled and not frame_version:
                dot15d4.aux_sec_header_2003.sec_framecounter=1
                    
            datagram_size = ipv6_pkt.plen + 40 # 40 is the length of the uncompressed ipv6 header

            pkt = self.forge_6lowpan_pkt(dot15d4, ipv6_pkt, mesh)
            
            self.send_pkt(pkt, datagram_size)


    def send_pkt(self, pkt, datagram_size):

        # Fragment it if necessary. If not the return value is a list of one element (pkt)
        #plist = self.lowpanfragment(pkt, self.hdr6_len, self.uncomp_hdr_len, datagram_size, self.datagram_tag)
        plist = self.lowpanfragment(pkt, self.datagram_tag)

        frag = len(plist) > 1 and True or False

        # Then send
        for p in plist:
            self.send(p)
            if frag: # Fragmented packet
                print "Sending fragment %d of packet" % plist.index(p)
                time.sleep(0.4)
            else:
                print "Sending unfragmented packet"

        if frag:
            self.datagram_tag += 1  # Increment datagram_tag 


    def forge_6lowpan_pkt(self, llpkt, ipv6_pkt, mesh=0):

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

        if mesh == 1:
            mesh_pkt = LoWPANMesh()
            mesh_pkt._sourceAddr = llpkt.src_addr
            mesh_pkt._v = (llpkt.fcf_srcaddrmode == 2) and 1 or 0
            mesh_pkt._destinyAddr = self.mesh_destinyAddr
            mesh_pkt._f = self.mesh_f
            
        # 2/ Forge packet headers.
        if mesh != 0:
            pkt = llpkt / SixLoWPAN() / mesh_pkt / LoWPAN_IPHC(tf=tf, nh=nh, hlim=hlim, tf_ecn=ecn, tf_dscp=dscp, tf_flowlabel=fl, hopLimit=ttl, nextHeader=nextHeader, sourceAddr=srcip, destinyAddr=dstip)
        else:
            pkt = llpkt / SixLoWPAN() / LoWPAN_IPHC(tf=tf, nh=nh, hlim=hlim, tf_ecn=ecn, tf_dscp=dscp, tf_flowlabel=fl, hopLimit=ttl, nextHeader=nextHeader, sourceAddr=srcip, destinyAddr=dstip)

        self.uncomp_hdr_len = 40 # IPv6 len before compression
        
        if nh:
            
            self.uncomp_hdr_len += 8 # Add UDP header len before compression
            pkt = pkt / self.forge_6lowpan_udp(llpkt, ipv6_pkt)

        pkt2 = pkt[Dot15d4FCS].copy()

        pkt2[Dot15d4Data].payload = NoPayload()
        
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


    def lowpandefragment(self, plist):
        
        return lowpandefragment(plist)
        
    #def lowpanfragment(self, pkt, hdr6_len, uncomp_hdr_len, datagram_size, datagram_tag):
        
    #    return lowpanfragment(pkt, hdr6_len, uncomp_hdr_len, datagram_size, datagram_tag)

    def lowpanfragment(self, pkt, datagram_tag):
        
        return lowpanfragment(pkt, datagram_tag)
        
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

        # Next header
        if iphc.nh:
            nh = 17 # UDP
            plen = 8 + len(iphc.payload.payload)
        else:
            nh = iphc.nextHeader # Normal cases : UDP/TCP/ICMPv6
            plen = len(iphc.payload)
            
        # Hop Limit
        ttl = ttl_values[str(iphc.hlim)]

        # Addressing information : they were automaticly uncompressed in dissection task
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

            #return IPv6(hdr + udp_hdr_str + udp_payload)
            return IPv6(hdr) / UDP(udp_hdr_str + udp_payload)  # to test
        
        elif pkt.nextHeader in [6,17,58]:

            ipv6_payload =  str(pkt[LoWPAN_IPHC].payload)            
            return IPv6(hdr + ipv6_payload)

        else:

            print "unknown packet format"
            return None

    def build_udp_header_from_lowpanudp(self, pkt):
        
        if LoWPAN_UDP in pkt:
            
            lowpan_udp = pkt[LoWPAN_UDP]

            # Ports
            sport = lowpan_udp.sport
            dport = lowpan_udp.dport
            
            # Len (udp header (8) + message(var) )
            length = 8 + len(lowpan_udp.payload)
            
            if lowpan_udp.chksumformat:
                chksum = None
            else:
                chksum = lowpan_udp.chksum                
            
            return str(UDP(sport=sport, dport=dport, len=lenght, chksum=chksum))  # !!!!! Missing underlayer IPv6 TODO

        return None



    def which_src_addr_to_use(self, mac_short_src, mac_long_src, ipv6_src):
            
        src_addr = None
            
        if mac_short_src != None and mac_long_src != None:
        # We have the choice! See if ipv6_dst derives from ll addr and make the choice consequently
            ipv6_src_str = socket.inet_pton(socket.AF_INET6, ipv6_src)

            if ipv6_src_str[8:14] == "\x00\x00\x00\xff\xfe\x00":

                if ipv6_src_str[14:16] == struct.pack('>H', mac_short_src):

                    fcf_srcaddrmode= 2
                    src_addr = mac_short_src

            else:

                tmp = struct.pack(">Q", mac_long_src)
                tmp = struct.pack("B", (struct.unpack("B", tmp[0])[0] ^ 0x2)) + tmp[1:8]
                
                if ipv6_src_str[8:] == tmp:

                    fcf_srcaddrmode= 3
                    src_addr = mac_long_src

                        
            if src_addr == None:
                # Use default conf
                    
                fcf_srcaddrmode = DEFAULT_SRC_ADDR_MODE
                
                if fcf_srcaddrmode == SHORT_ADDR_MODE:
                    src_addr = mac_short_src
                else:
                    src_addr = mac_long_src

        elif mac_short_src != None:

            fcf_srcaddrmode= 2
            src_addr = mac_short_src
                
        elif mac_long_src != None:
            
            fcf_srcaddrmode= 3
            src_addr = mac_long_src

        return fcf_srcaddrmode, src_addr


    def get_transmission_conf(self, src_addr, dest_addr, src_panid, dest_panid):
                
        security_level = 0
        
        if conf.dot15d4_database != None:

            security_enabled, frame_version = dot15d4_db_get_transmission_conf(conf.dot15d4_database, src_addr, dest_addr, src_panid, dest_panid)
                    
            if security_enabled == None and frame_version ==None:
                # We don't found this entry in database, using default conf

                security_enabled = DEFAULT_SECURITY_ENABLED
                frame_version = DEFAULT_FRAME_VER

                if security_enabled:

                    if frame_version == 0:
                        conf.dot15d4securitysuite = DEFAULT_SECURITY_POLICY
                    else:
                        security_level = DEFAULT_SECURITY_POLICY

                        
        else:

            security_enabled = DEFAULT_SECURITY_ENABLED
            frame_version = DEFAULT_FRAME_VER

            if security_enabled:

                if frame_version == 0:
                    conf.dot15d4securitysuite = DEFAULT_SECURITY_POLICY
                else:
                    security_level = DEFAULT_SECURITY_POLICY

        return security_enabled, frame_version, security_level

    

    def which_dest_addr_to_use(self, mac_short_dest, mac_long_dest, ipv6_dst):
            
        dest_addr = None

        # We have the choice! See if ipv6_dst derives from ll addr and make the choice consequently            
        if mac_short_dest != None and mac_long_dest != None:

            ipv6_dst_str = socket.inet_pton(socket.AF_INET6, ipv6_dst)
            
            if ipv6_dst_str[8:14] == "\x00\x00\x00\xff\xfe\x00":
                
                if ipv6_dst_str[14:16] == struct.pack('>H', mac_short_dest):

                    fcf_destaddrmode= 2
                    dest_addr = mac_short_dest

            else:

                tmp = struct.pack(">Q", mac_long_dest)
                tmp = struct.pack("B", (struct.unpack("B", tmp[0])[0] ^ 0x2)) + tmp[1:8]

                if ipv6_dst_str[8:] == tmp:

                    fcf_destaddrmode= 3
                    dest_addr = mac_long_dest

                        
            if dest_addr == None:
                # Use default conf

                fcf_destaddrmode = DEFAULT_DEST_ADDR_MODE

                if fcf_destaddrmode == SHORT_ADDR_MODE:
                    dest_addr = mac_short_dest
                else:
                    dest_addr = mac_long_dest

        elif mac_short_dest != None:
            
            fcf_destaddrmode= 2
            dest_addr = mac_short_dest
                
        elif mac_long_dest != None:
            
            fcf_destaddrmode= 3
            dest_addr = mac_long_dest


        return fcf_destaddrmode, dest_addr
                
                
def create_tap(my_ipv6):

    ######  CREATING TAP ######

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
    time.sleep(0.5)
    fcntl.ioctl(tun, TUNSETIFF, ifr)

    os.system('ip link set tun0 up')
    os.system("/sbin/ifconfig tun0 inet6 add " + my_ipv6  + "/64")

    return tun


def launch_gnuradio(channel):

    ###### LAUNCHING GNURADIO #####

    load_module('gnuradio')
    conf.L2listen=GnuradioSocket_in
    conf.L3socket=GnuradioSocket_out

    switch_radio_protocol("dot15d4")
    print "Launching Gnuradio in background..."
    time.sleep(5)
    gnuradio_set_vars(Channel=channel)

    
if __name__ == '__main__':


    print "\n\t\t\tWelcome to IPv6 - SixLoWPAN Border Router"
    print
    print

    channel = ui_choose_channel()
    ui_choose_database()

    ndp_table = user_ndp_table

    if conf.dot15d4_database != None:

        ndp_table.update(dot15d4_get_ndp_table(conf.dot15d4_database))
        
    print
    print "NDP Table : "

    for k, v in ndp_table.items():
        print "\t%s : %s" % (k,str(v))
    
    my_ipv6 = ui_choose_ipv6_addr()

    check_ndp_table(ndp_table, my_ipv6)
    
    tun = create_tap(my_ipv6)

    launch_gnuradio(channel)
    
    ##### LAUCHING BORDER ROUTER #####

    init = 0

    router = BorderRouter(my_ipv6, ndp_table, external_fd={"my_events":tun})

    router.run()

            
