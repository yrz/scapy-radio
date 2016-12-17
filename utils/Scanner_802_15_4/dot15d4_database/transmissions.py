from security import *
from scapy.layers.inet import *
import socket

class sixlowpan_addr(object):

    def __init__(self, src, dst):

        self.src = src
        self.dst = dst

    def get_dict(self):
        return {'src':self.src, 'dst':self.dst}

    def show(self, opt=''):
        print "%sSixlowpan" % opt
        print "%s src = %s" % (opt,self.src)
        print "%s dst = %s" % (opt,self.dst)


class Transmission(object):

    valid_attr = {
        "frametype" : lambda x: x in [0,1,3],
        "framesubtype" : lambda x: x in [1,2,3,4,5,6,7,8,9],
        'security_enabled' : lambda x: x==0 or x==1,
        'frame_version' : lambda x: x == 0 or  x == 1,
        'indirect_transmission' :  lambda x: x == 0 or x == 1,
        'srcaddrmode' : lambda x: ((x == 0) or  (x == 2) or (x == 3)),
        'destaddrmode' : lambda x: ((x == 0) or  (x == 2) or (x == 3)),
    }


    def __init__(self, owner, pkt, **kwargs):

        self.__dict__.update((k, v) for k, v in kwargs.iteritems() if (k in self.valid_attr) and self.valid_attr[k](v))
        self.counter = 1
        self.originator = owner
        self.packets_buffer = [pkt]

        if self.security_exist():
            self.__dict__.update({'security' : SecurityFeatures(security_policy = kwargs.get('security_policy', None) )})


    def __getattr__(self, attr):
        return self.__dict__.get(attr,None)
                

    def get_dict(self):

        js = {}
        
        for k,v in self.__dict__.iteritems():

            if self.valid_attr.has_key(k):
               js[k] = v

        if self.security_exist():
            js['Security'] = self.security.get_dict()

        if self.sixlowpan != None:
            js['Sixlowpan'] = self.sixlowpan.get_dict()

        return js


    def look_for_sixlowpan(self):

        if self.frametype != 1:
            return

        if self.security != None and self.security.security_found == False:
            # Would not be able to unsecured frame
            return
        
        sixlowpan = False
        
        # Unsecure frames
        for p in self.packets_buffer:

            pkt = p.copy()

            pkt = pkt[Dot15d4FCS]

            if self.security != None:
                
                if self.frame_version == 1:

                    frame_counter = pkt.aux_sec_header.sec_framecounter
                    key_seq_counter = None

                else:

                    frame_counter = pkt.aux_sec_header_2003.sec_framecounter
                    key_seq_counter = pkt.aux_sec_header_2003.sec_keyseqcounter
                        

                header = pkt.get_mhr() + pkt.payload.get_nonpayload_fields()
                ciphertext = pkt.payload.get_payload_fields()
                src_addr = self.originator.addr64
                        

                text = cipherDot15d4Unsecure(ciphertext,
                                             header,
                                             self.security.key[2:],
                                             self.security.security_policy,
                                             frame_counter,
                                             self.originator.addr64,
                                             key_seq_counter,
                                             **self.security.deviations_list)[0]


                ll_pkt = Dot15d4FCS(header)
                _6lp_pkt = SixLoWPAN(_pkt=text, _underlayer=ll_pkt[Dot15d4Data])

                pkt = ll_pkt / _6lp_pkt


            if SixLoWPAN in pkt:

                if isinstance(pkt[SixLoWPAN].payload, LoWPANMesh):

                    if isinstance(pkt[LoWPANMesh].payload, LoWPAN_IPHC):

                        if pkt[LoWPAN_IPHC].nextHeader in [6,17,58]:
                            # consider it is a sixlowpan pkt
                            sixlowpan = True
                            src = pkt[LoWPAN_IPHC].sourceAddr
                            dst = pkt[LoWPAN_IPHC].destinyAddr
                            break

                    elif isinstance(pkt[LoWPANMesh].payload, LoWPANUncompressedIPv6):

                        if pkt[LoWPANUncompressedIPv6].version == 6:
                                # consider it is a sixlowpan pkt
                                sixlowpan = True
                                src = pkt[IPv6].src
                                dst = pkt[IPv6].dst
                                break

                    elif isinstance(pkt[LoWPANMesh].payload, LoWPANFragmentationFirst):

                        if isinstance(pkt[LoWPANFragmentationFirst].payload, LoWPAN_IPHC):

                            if pkt[LoWPAN_IPHC].nextHeader in [6,17,58]:
                                # consider it is a sixlowpan pkt
                                sixlowpan = True
                                src = pkt[LoWPAN_IPHC].sourceAddr
                                dst = pkt[LoWPAN_IPHC].destinyAddr
                                break

                            elif str(pkt[LoWPANFragmentationFirst].payload)[0] == '\x41': #IPv6

                                if (str(pkt[LoWPANFragmentationFirst].payload)[1] >> 4) == 6:
                                    # consider it is a sixlowpan pkt
                                    sixlowpan = True
                                    src = socket.inet_ntop(socket.AF_INET6, str(pkt[LoWPANFragmentationFirst].payload)[9:25])
                                    dst = socket.inet_ntop(socket.AF_INET6, str(pkt[LoWPANFragmentationFirst].payload)[25:41])
                                    break
                                        
                    elif isinstance(pkt[LoWPANMesh].payload, LoWPANFragmentationSubsequent):
                        # Address not present in this kind of packet
                        continue

                    elif isinstance(pkt[LoWPANMesh].payload, LoWPANBroadcast):

                        if isinstance(pkt[LoWPANBroadcast].payload, LoWPAN_IPHC):

                            if pkt[LoWPAN_IPHC].nextHeader in [6,17,58]:
                                # consider it is a sixlowpan pkt
                                sixlowpan = True
                                src = pkt[LoWPAN_IPHC].sourceAddr
                                dst = pkt[LoWPAN_IPHC].destinyAddr
                                break

                        elif isinstance(pkt[LoWPANBroadcast].payload, LoWPANUncompressedIPv6):

                            if pkt[LoWPANUncompressedIPv6].version == 6:
                                # consider it is a sixlowpan pkt
                                sixlowpan = True
                                src = pkt[IPv6].src
                                dst = pkt[IPv6].dst
                                break

                        elif isinstance(pkt[LoWPANBroadcast].payload, LoWPANFragmentationFirst):

                            if isinstance(pkt[LoWPANFragmentationFirst].payload, LoWPAN_IPHC):

                                if pkt[LoWPAN_IPHC].nextHeader in [6,17,58]:
                                    # consider it is a sixlowpan pkt
                                    sixlowpan = True
                                    src = pkt[LoWPAN_IPHC].sourceAddr
                                    dst = pkt[LoWPAN_IPHC].destinyAddr
                                    break

                            elif str(pkt[LoWPANFragmentationFirst].payload)[0] == '\x41': #IPv6

                                if (str(pkt[LoWPANFragmentationFirst].payload)[1] >> 4) == 6:
                                    # consider it is a sixlowpan pkt
                                    sixlowpan = True
                                    src = socket.inet_ntop(socket.AF_INET6, str(pkt[LoWPANFragmentationFirst].payload)[9:25])
                                    dst = socket.inet_ntop(socket.AF_INET6, str(pkt[LoWPANFragmentationFirst].payload)[25:41])
                                    break
                                    
                        elif isinstance(pkt[LoWPANBroadcast].payload, LoWPANFragmentationSubsequent):
                            # Address not present in this kind of pkt
                            continue

                elif isinstance(pkt[SixLoWPAN].payload, LoWPANUncompressedIPv6):

                    if pkt[LoWPANUncompressedIPv6].version == 6:
                        # consider it is a sixlowpan pkt
                        sixlowpan = True
                        src = pkt[IPv6].src
                        dst = pkt[IPv6].dst
                        break

                elif isinstance(pkt[SixLoWPAN].payload, LoWPANFragmentationFirst):
                    
                    if isinstance(pkt[LoWPANFragmentationFirst].payload, LoWPAN_IPHC):
                        
                        if pkt[LoWPAN_IPHC].nextHeader in [6,17,58]:
                            # consider it is a sixlowpan pkt
                            sixlowpan = True
                            src = pkt[LoWPAN_IPHC].sourceAddr
                            dst = pkt[LoWPAN_IPHC].destinyAddr
                            break

                    elif str(pkt[LoWPANFragmentationFirst].payload)[0] == '\x41': #IPv6

                        if (str(pkt[LoWPANFragmentationFirst].payload)[1] >> 4) == 6:
                            # consider it is a sixlowpan pkt
                            sixlowpan = True
                            src = socket.inet_ntop(socket.AF_INET6, str(pkt[LoWPANFragmentationFirst].payload)[9:25])
                            dst = socket.inet_ntop(socket.AF_INET6, str(pkt[LoWPANFragmentationFirst].payload)[25:41])
                            break
                            

                elif isinstance(pkt[SixLoWPAN].payload, LoWPANFragmentationSubsequent):
                    # Address not present in this kind of pkt
                    continue

                elif isinstance(pkt[SixLoWPAN].payload, LoWPAN_IPHC):                        

                    if pkt[LoWPAN_IPHC].nextHeader in [6,17,58]:
                        # consider it is a sixlowpan pkt
                        sixlowpan = True
                        src = pkt[LoWPAN_IPHC].sourceAddr
                        dst = pkt[LoWPAN_IPHC].destinyAddr
                        break


                else:
                    # Not a sixlowpan packet
                    continue
                            
        if sixlowpan:
            # Add sixlowpan addr to transmission parameters
            self.sixlowpan = sixlowpan_addr(src, dst)
    
        
    def feed(self, pkt):
        self.counter += 1
        try:
            self.packets_buffer.append(pkt)
        except:
            print "Packet buffer is full"
            self.counter = len(self.packets_buffer)

        
    def merge(self, transmission):
        
        self.counter += transmission.counter
        
        try:
            self.packets_buffer.extend(transmission.packets_buffer)
        except:
            print "Packet buffer is full"
            self.counter = len(self.packets_buffer)

    def security_exist(self):
        return self.security_enabled


    def unknown_security_policy(self):
        
        if not self.security_exist():
            return False
            
        if self.security.security_found:
            return False

        return True


    def guess_deviation(self):
        
        if self.unknown_security_policy():
            self.security.guess_deviation(self, self.packets_buffer, self.frame_version)

    def guess_security(self):
        
        if not self.security_exist():
            return
                    
        self.security.guess_security(self, self.packets_buffer, self.frame_version)
        
    def handle_encryption_key(self, key=''):
        
        # check if security has been enabled
        if not self.security_exist():
            return

        if key == '':
            print "Security has been used for the following transmission : \n"

            while(1):
                
                self.show_light(opt='\t')
                print "\n******************************************************\n"

                key = raw_input("Provide the 16 bytes encryption key used for the transmission printed above (format = 0xAAAAAAAAAAAAAAAA) : ")
                if key and key[:2] == "0x" and len(key[2:]) == 32:
                    try:
                        int(key,16)
                        break
                    except Exception:
                        pass

        self.security.key = key
            
            

    def get_parameters(self):
        parameters = {}
        parameters.update((k,v) for k, v in self.__dict__.iteritems() if (k in self.valid_attr))
        return parameters
            
    def has_same_parameters(self, parameters):

        filtred_parameters = {}
        filtred_parameters.update((k,v) for k,v in parameters.iteritems() if (k in self.valid_attr) and self.valid_attr[k](v))

        return (not cmp(self.get_parameters(), filtred_parameters))


    def show_light(self, opt=''):

        print "%sParameters" % opt

        for k,v in self.get_parameters().iteritems():
            if (k in self.valid_attr):            
                print "%s %s = 0x%x" % (opt,k,v)
        

    def show(self, opt=''):
        print "%sParameters" % opt
        for k,v in self.get_parameters().iteritems():
                print "%s %s = 0x%x" % (opt,k,v)
        
        if self.security != None:
            self.security.show(opt=opt)

        if self.sixlowpan != None:
            self.sixlowpan.show(opt=opt)
            
        print " %sCounter = %d" % (opt, self.counter)

        print " %sPackets stored are" % opt

        for p in self.packets_buffer:
            
            if len(p) > 50:
                print "%s %s ... %s  " % (opt , str(p)[:25].encode('hex') , str(p)[-25:].encode('hex'))
            else:
                print "%s  " % opt + str(p).encode('hex')
