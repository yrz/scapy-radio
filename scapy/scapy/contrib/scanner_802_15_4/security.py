from scapy.all import *
from entropy import *
from scapy.crypto.AESCCMDot15d4 import *
from config import *
from lxml import etree

class SecurityFeatures(object):

        valid_attr = {
                "security_found" : lambda x: x in [0,1],
                "deviation_found" : lambda x: x in [0,1],
                "security_policy" : lambda x: x in [i for i in range(1,8)],
                "deviations_list" : lambda x : isinstance(x, tuple),
                "encryption_flag" : lambda x : x >= 0 and x<= 0xff,
                "authentication_flag" : lambda x : x >= 0 and x<= 0xff,
        }

        def __init__(self, **kwargs):
            for k,v in kwargs.iteritems():
                self.__setattr__(k,v)

        def __getattr__(self, attr):
            return self.__dict__.get(attr,None)

        def __setattr__(self, attr, val):
            if attr in self.valid_attr and self.valid_attr[attr](val):
                self.__dict__[attr] = val
                
        def generate_xml(self):
                
                security = etree.Element("SecurityFeatures")

                for k,v in self.__dict__.iteritems():
                        element = etree.Element(k)
                        if k != 'deviations_list':
                                element.text = hex(v)
                                if element.text[-1] == 'L':
                                        element.text = element.text[:-1]
                        else:
                                element.text = str(v)

                        security.append(element)

                return security
                        

        def show(self, opt=''):
            
            print "%sSecurity Features" % opt
            
            for k,v in self.__dict__.iteritems():
                if k == 'deviations_list':
                        print '%s %s = %s' % (opt, k,v)
                else:
                        print "%s %s = 0x%x" % (opt, k, v)
            
        def is_payload_valid(self,payload, pkt):

                if not payload:
                        return False

                for s in security_conf.strings_to_detect:
                        if s in payload:
                                return True    

                # Look for protocol indicated in security_conf.protocol_to_detect
                for k, v in  security_conf.protocol_to_detect.iteritems():
                        if v(payload, pkt):
                                return True
                        
                if calcul_data_entropy(payload) < security_conf.entropy:
                        return True


                return False


        def secure_frame(self, text, framever, pkt, _key, header):

                if framever:  # 2006
                        # TODO
                        return text

                else:  # 2003

                        key = _key
                        
                        srcaddr64 = pkt.src_addr

                        frame_counter = pkt.sec_framecounter

                        key_seq_counter = pkt.sec_keyseqcounter

                        if self.security_found == True:
                                
                                if self.security_policy == 4:
                                
                                        if self.deviation_found == True:

                                                if self.deviations_list != None:

                                                        devs = self.deviations_list

                                                        if 'dev1' in devs:
                                                                sec_dev = True
                                                        else:
                                                                sec_dev = False
                                        
                                                        if 'dev3' in devs:
                                                                counter_dev = True
                                                        else:
                                                                counter_dev = False
                                
                                                        if 'dev2' in devs:

                                                                flag = self.encryption_flag
                                                                
                                                        plaintext = AES_CTR(text, key[2:],
                                                                            frame_counter,
                                                                            srcaddr64,
                                                                            key_seq_counter,
                                                                            Sec_level=sec_dev,
                                                                            Flag=flag,
                                                                            Counter=counter_dev)
                                                        return plaintext

                                                else: 
                                                        print 'Cannot secured frame, the deviations list is missing!'
                                                        return text

                                                
                                        else:
                                        
                                                plaintext = AES_CTR(text, key[2:],
                                                                    frame_counter,
                                                                    srcaddr64,
                                                                    key_seq_counter)

                                                return plaintext

                                elif self.security_policy > 4:
                                
                                        print 'TODO security policy > 4'
                                        return text
                                        
                                else:
                                        
                                        print 'Authentication only policy not handled yet for 2003 frame '
                                        return text
                                        
                                        

                        else:
                                print 'Cannot secure frame, security has not be determined during the scan'
                                return text
                
                
                


        def unsecure_frame(self, text, framever, pkt, _key):
                
                if framever:  # 2006
                        # TODO
                        return text

                else:  # 2003
                        
                        key = _key
                        
                        try:
                                srcaddr64 = pkt.underlayer.src_addr
                        except:
                                srcaddr64 = pkt.src_addr

                        frame_counter = pkt.sec_framecounter

                        key_seq_counter = pkt.sec_keyseqcounter

                        if self.security_found == True:
                                
                                if self.security_policy == 4:
                                
                                        if self.deviation_found == True:

                                                if self.deviations_list != None:

                                                        devs = self.deviations_list

                                                        if 'dev1' in devs:
                                                                sec_dev = True
                                                        else:
                                                                sec_dev = False
                                        
                                                        if 'dev3' in devs:
                                                                counter_dev = True
                                                        else:
                                                                counter_dev = False
                                
                                                        if 'dev2' in devs:

                                                                flag = self.encryption_flag
                                                                

                                                        plaintext = AES_CTR(text, key[2:],
                                                                            frame_counter,
                                                                            srcaddr64,
                                                                            key_seq_counter,
                                                                            Sec_level=sec_dev,
                                                                            Flag=flag,
                                                                            Counter=counter_dev)
                                                        return plaintext

                                                else: 
                                                        print 'Cannot unsecured frame, the deviations list is missing!'
                                                        return text

                                                
                                        else:
                                        
                                                plaintext = AES_CTR(text, key[2:],
                                                                    frame_counter,
                                                                    srcaddr64,
                                                                    key_seq_counter)

                                                return plaintext

                                elif self.security_policy > 4:
                                
                                        print 'TODO security policy > 4'
                                        return text
                                        
                                else:
                                        
                                        print 'Authentication only policy not handled yet for 2003 frame '
                                        return text
                                        
                                        

                        else:
                                print 'Cannot unsecure frame, secururity has not be detrmined during the scan'
                                return text
                                                


        def guess_deviation(self, trans, pkt, key, frame_ver):


                for p in pkt:

                        if frame_ver: # 2006
                                result = self.guess_deviation_2006(trans, p, key, frame_ver)
                                

                        else: # 2003
                                result = self.guess_deviation_2003(trans, p, key, frame_ver)

                        if result == True:
                                break

                        #if not self.security_found:
                        
                        version_dev = security_conf.version_deviations
                                
                        if frame_ver and 'dev19' in version_dev: # 2006
                                
                                try:
                                        result = self.guess_deviation_2003(trans, p, key, frame_ver)

                                        if result == True:
                                                break
                                        
                                except:
                                        pass

                        elif not frame_ver and 'dev18' in version_dev: # 2003

                                try:
                                        self.guess_deviation_2006(trans, p, key, frame_ver)                                

                                        if result == True:
                                                break
                                except:
                                        pass
                                        
                                
        


        def guess_deviation_2003(self, trans, pkt, key, frame_ver):
                

                wrong_standard = 0                

                if security_conf.max_deviations == 0:
                        return False

                if frame_ver:
                        # Convert 2006 frame to 2003 frame

                        wrong_standard = 1

                        pkt.fcf_framever = 0
                        pkt = GnuradioPacket(str(pkt))
                        self.guess_security_2003(trans, pkt, key, frame_ver)
                                
                        if self.security_found:
                                self.deviation_found=True
                                self.deviations_list = ('dev19',)
                                return True


                # Note : Authentication only policy (CBC-MAC) is not handled yet 

                dev_ctr = security_conf.ctr_deviations
                dev_ccm = security_conf.ccm_deviations

                # No deviations to look for : either the max_deviation is 0 or the lists of 
                # deviations to check is empty!
                if not dev_ctr and not dev_ccm :
                        print 'No deviation to look for'
                        return False

                p = pkt[Dot15d4FCS]

                if p.payload.payload.__class__ != Dot15d4AuxSecurityHeader2003:
                        print "Malformatted secured packet"
                        return False

                if p.payload.payload.payload != None:
        
                        # Retrieve Payload
                        pay = str(p.payload.payload.payload)
                        
                        # Look for AES-CTR and AES-CCM security policy
                        if p.fcf_srcaddrmode != 3:  
            
                                # Extended src short address not present 
                                # It is part of the keying material used to secure the frame
                                # See if we could have retrieved it during the scan
            
                                srcaddr64 = trans.originator.addr64
                
                        else:
                                
                                srcaddr64 = p.src_addr

        
                        if srcaddr64 == None:
                                print "Could not retrieve the extended src address needed to unsecure the frame"
                                return False

                        # Retrieve Header
                        if p.__class__ == Dot15d4FCS:
                                head = p.copy()
                                head.payload.payload.payload = ''
                                head = str(head)[:-2] # remove FCS

                        key = key[2:]  # remove '0x'

                        frame_counter = p.sec_framecounter
                        key_seq_counter = p.sec_keyseqcounter

                else:
                        print 'Malformated packet'
                        return False


                # Handle CTR deviations

                # Listing every combination of deviation (depending on the max_deviations value) 
                deviation_comb = []

                for comb in range(1, security_conf.max_deviations - wrong_standard + 1):

                        tmp = []
                        c = itertools.combinations(dev_ctr, comb)

                        for dev in c:
                                tmp.append(dev)
                
                        deviation_comb.append(tmp)

                # Looking for every combination of deviations (CTR) we listed above
                for c in deviation_comb:

                 for comb in c:

                        if 'dev1' in comb:
                                sec_dev = True
                        else:
                                sec_dev = False
                                        
                        if 'dev3' in comb:
                                counter_dev = True
                        else:
                                counter_dev = False
                                
                        if 'dev2' in comb:

                                # Let's bruteforce the flag
                                for i in xrange(pow(2,8)):
                                        plaintext = AES_CTR(pay, key,
                                                            frame_counter,
                                                            srcaddr64,
                                                            key_seq_counter,
                                                            Sec_level=sec_dev,
                                                            Flag=i,
                                                            Counter=counter_dev)
                                        
                                        if self.is_payload_valid(plaintext, pkt):
                                                self.security_found = True
                                                self.deviation_found = True
                                                self.security_policy = 4
                                                self.deviations_list = comb
                                                self.encryption_flag = i
                                                if wrong_standard:
                                                        self.deviations_list = self.deviations_list + ('dev19',)
                                                return True

                                                
                                                
                    
                        else: 
                                plaintext = AES_CTR(pay,
                                                  key,
                                                  frame_counter,
                                                  srcaddr64,
                                                  key_seq_counter,
                                                  Sec_level=sec_dev,
                                                  Counter=counter_dev)

                                if self.is_payload_valid(plaintext, pkt):
                                        self.security_found = True
                                        self.deviation_found = True
                                        self.security_policy = 4
                                        self.deviations_list = comb
                                        if wrong_standard:
                                                self.deviations_list = self.deviations_list + ('dev19',)
                                        return True

                                        
                # Handle CCM deviations

                # Listing every combination of deviation (depending on the max_deviations value) 
                deviation_comb = []

                for comb in range(1, security_conf.max_deviations - wrong_standard + 1):

                        tmp = []
                        c = itertools.combinations(dev_ccm, comb)

                        for dev in c:
                                tmp.append(dev)
                
                        deviation_comb.append(tmp)


                
                # Looking for every combination of deviations (CTR) we listed above
                for security_level in range(5, 8):

                  for c in deviation_comb:

                    for comb in c:

                        if 'dev4' in comb:
                                 sec_dev = True
                        else:
                                 sec_dev = False
                    
                        if 'dev6' in comb:
                                auth_tag_dev = True
                        else:
                                auth_tag_dev = False

                        if 'dev8' in comb:
                                enc_block_dev = True
                        else:
                                enc_block_dev = False

                        if 'dev9' in comb:
                                enc_tag_dev1 = True
                        else:
                                enc_tag_dev1 = False

                        if 'dev10' in comb:
                                enc_tag_dev2 = True
                        else:
                                enc_tag_dev2 = False

                
                        if 'dev7' in comb:
                    
                                for i in xrange(pow(2,8)):
                        
                                        if 'dev5'in comb:

                                                for j in xrange(pow(2,8)):
                                
                                                        integrity, plaintext = AES_CCM(pay,
                                                                                       key,
                                                                                       security_level,
                                                                                       frame_counter,
                                                                                       srcaddr64,
                                                                                       encrypt=False,
                                                                                       header=head,
                                                                                       keyseqcounter=key_seq_counter,
                                                                                       sec_dev=sec_dev,
                                                                                       auth_flag_dev=j,
                                                                                       auth_tag_dev=auth_tag_dev,
                                                                                       enc_flag_dev=i,
                                                                                       enc_block_dev=enc_block_dev,
                                                                                       enc_tag_dev1=enc_tag_dev1,
                                                                                       enc_tag_dev2=enc_tag_dev2)


                                                        if integrity and self.is_payload_valid(plaintext, pkt):
                                                                self.security_found = True
                                                                self.deviation_found = True
                                                                self.security_policy = security_level
                                                                self.deviations_list = comb
                                                                self.encryption_flag = i
                                                                self.authentication_flag = j
                                                                if wrong_standard:
                                                                        self.deviations_list = self.deviations_list + ('dev19',)
                                                                return True

                                                                


                                        else:
                            
                                                integrity, plaintext = AES_CCM(pay,
                                                                               key,
                                                                               security_level,
                                                                               frame_counter,
                                                                               srcaddr64,
                                                                               encrypt=False,
                                                                               header=head,
                                                                               keyseqcounter=key_seq_counter,
                                                                               sec_dev=sec_dev,
                                                                               auth_flag_dev=None,
                                                                               auth_tag_dev=auth_tag_dev,
                                                                               enc_flag_dev=i,
                                                                               enc_block_dev=enc_block_dev,
                                                                               enc_tag_dev1=enc_tag_dev1,
                                                                               enc_tag_dev2=enc_tag_dev2)

                                                if integrity and self.is_payload_valid(plaintext, pkt):
                                                        self.security_found = True
                                                        self.deviation_found = True
                                                        self.security_policy = security_level
                                                        self.deviations_list = comb
                                                        self.encryption_flag = i
                                                        if wrong_standard:
                                                                self.deviations_list = self.deviations_list + ('dev19',)
                                                        return True

                        elif 'dev5' in comb:

                                for i in xrange(pow(2,8)):

                                        integrity, plaintext = AES_CCM(pay,
                                                                       key,
                                                                       security_level,
                                                                       frame_counter,
                                                                       srcaddr64,
                                                                       encrypt=False,
                                                                       header=head,
                                                                       keyseqcounter=key_seq_counter,
                                                                       sec_dev=sec_dev,
                                                                       auth_flag_dev=i,
                                                                       auth_tag_dev=auth_tag_dev,
                                                                       enc_flag_dev=None,
                                                                       enc_block_dev=enc_block_dev,
                                                                       enc_tag_dev1=enc_tag_dev1,
                                                                       enc_tag_dev2=enc_tag_dev2)
                        
                        
                                        if integrity and self.is_payload_valid(plaintext, pkt):
                                                self.security_found = True
                                                self.deviation_found = True
                                                self.security_policy = security_level
                                                self.deviations_list = comb
                                                self.authentication_flag = i
                                                if wrong_standard:
                                                        self.deviations_list = self.deviations_list + ('dev19',)
                                                return True

                        else:

                                integrity, plaintext = AES_CCM(pay,
                                                               key,
                                                               security_level,
                                                               frame_counter,
                                                               srcaddr64,
                                                               encrypt=False,
                                                               header=head,
                                                               keyseqcounter=key_seq_counter,
                                                               sec_dev=sec_dev,
                                                               auth_flag_dev=None,
                                                               auth_tag_dev=auth_tag_dev,
                                                               enc_flag_dev=None,
                                                               enc_block_dev=enc_block_dev,
                                                               enc_tag_dev1=enc_tag_dev1,
                                                               enc_tag_dev2=enc_tag_dev2)                            

                                
                                if integrity and self.is_payload_valid(plaintext, pkt):
                                        self.security_found = True
                                        self.deviation_found = True
                                        self.security_policy = security_level
                                        self.deviations_list = comb
                                        if wrong_standard:
                                                self.deviations_list = self.deviations_list + ('dev19',)
                                        return True

                print 'Deviation not found' 
                return False


        def guess_deviation_2006(self, trans, pkt, key, frame_ver):


                wrong_standard = 0                

                if security_conf.max_deviations == 0:
                        return False

                if not frame_ver:
                        # Convert 2003 frame to 2006 frame

                        wrong_standard = 1
                        pkt.fcf_framever = 1
                        pkt = GnuradioPacket(str(pkt))
                        self.guess_security_2006(trans, pkt, key, frame_ver)
                                
                        if self.security_found:
                                self.deviation_found=True
                                self.deviations_list = ('dev18',)
                                return True

                dev_ccm_star = security_conf.ccm_star_deviations

                # No deviations to look for : either the max_deviation is 0 or the list of 
                # deviations to check is empty!
                if not dev_ccm_star:
                        print 'No deviation to look for'
                        return False

                p = pkt[Dot15d4FCS]

                if p.payload.payload.__class__ != Dot15d4AuxSecurityHeader:                
                        p.show()
                        print "Malformatted secured packet 1 "
                        return False

                if p.payload.payload.payload != None:
        
                        if p.fcf_srcaddrmode != 3:  
            
                                # Extended src short address not present 
                                # It is part of the keying material used to secure the frame
                                # See if we could have retrieved it during the scan
            
                                srcaddr64 = trans.originator.addr64
                
                        else:
                                
                                srcaddr64 = p.src_addr

        
                        if srcaddr64 == None:
                                print "Could not retrieve the extended src address needed to unsecure the frame"
                                return False

                        # Retrieve Payload
                        pay = str(p.payload.payload.payload)
        
                        # Retrieve Header
                        if p.__class__ == Dot15d4FCS:
                                head = p.copy()
                                head.payload.payload.payload = ''
                                head = str(head)[:-2] # remove FCS

                        # Retrieve the security level and the frame counter
                        frame_counter = p.sec_framecounter

                        key = key[2:]  # remove '0x'


                else:
                        print 'Malformated Packet'
                        return False

                # Listing every combination of deviation (depending on the max_deviations value) 
                deviation_comb = []

                for comb in range(1, security_conf.max_deviations - wrong_standard + 1):

                        tmp = []
                        c = itertools.combinations(dev_ccm_star, comb)

                        for dev in c:
                                tmp.append(dev)
                
                        deviation_comb.append(tmp)


                for security_level in range(1,8):


                       # Looking for every combination of deviations we listed above
                       for c in deviation_comb:

                        for comb in c:

                                if 'dev17' in comb:
                                        nonce_dev = True
                                else:
                                        nonce_dev = False
                                        
                                if 'dev12' in comb:
                                        auth_tag_dev = True
                                else:
                                        auth_tag_dev = False
                                
                                if 'dev14' in  comb:
                                        enc_block_dev = True
                                else:
                                        enc_block_dev = False
            
                                if 'dev15' in comb:
                                        enc_tag_dev1 = True
                                else:
                                        enc_tag_dev1 = False
        
                                if 'dev16' in comb:
                                        enc_tag_dev2 = True
                                else:
                                        enc_tag_dev2 = False
                        
                                if 'dev13' in comb:
                                        
                                        # Let's bruteforce the flag octet for encryption
                                        for i in xrange(pow(2,8)):
                                                
                                                if 'dev11' in comb:

                                                        # Let's bruteforce the flag octet for authentication too
                                                        for j in xrange(pow(2,8)):
                                                        
                                                                integrity, plaintext = AES_CCM(pay, key,
                                                                                               security_level,
                                                                                               frame_counter,
                                                                                               srcaddr64,
                                                                                               encrypt=False,
                                                                                               header=head,
                                                                                               auth_flag_dev=j,
                                                                                               auth_tag_dev=auth_tag_dev,
                                                                                               enc_flag_dev=i,
                                                                                               enc_block_dev=enc_block_dev,
                                                                                               enc_tag_dev1=enc_tag_dev1,
                                                                                               enc_tag_dev2=enc_tag_dev2,
                                                                                               nonce_dev=nonce_dev)

                                                                if self.is_payload_valid(plaintext, pkt) and integrity:
                                                                        self.security_found = True
                                                                        self.deviation_found = True
                                                                        self.security_policy = security_level
                                                                        self.deviations_list = comb
                                                                        self.encryption_flag = i
                                                                        self.authentication_flag = j
                                                                        if wrong_standard:
                                                                                self.deviations_list = self.deviations_list + ('dev18',)
                                                                        
                                                                        return True
                                                else:
                                                        
                                                        integrity, plaintext=AES_CCM(pay,
                                                                                     key,
                                                                                     security_level,
                                                                                     frame_counter,
                                                                                     srcaddr64,
                                                                                     encrypt=False,
                                                                                     header=head,
                                                                                     auth_flag_dev=None,
                                                                                     auth_tag_dev=auth_tag_dev,
                                                                                     enc_flag_dev=i,
                                                                                     enc_block_dev=enc_block_dev,
                                                                                     enc_tag_dev1=enc_tag_dev1,
                                                                                     enc_tag_dev2=enc_tag_dev2,
                                                                                     nonce_dev=nonce_dev)

                                                        if self.is_payload_valid(plaintext, pkt) and integrity:
                                                                self.security_found = True
                                                                self.deviation_found = True
                                                                self.security_policy = security_level
                                                                self.deviations_list = comb # + frame version
                                                                self.encryption_flag = i
                                                                if wrong_standard:
                                                                        self.deviations_list = self.deviations_list + ('dev18',)
                                                                return True
                                        
                                elif 'dev11' in comb:
                                        
                                        for i in xrange(pow(2,8)):

                                                integrity, plaintext = AES_CCM(pay,
                                                                               key,
                                                                               security_level,
                                                                               frame_counter,
                                                                               srcaddr64,
                                                                               encrypt=False,
                                                                               header=head,
                                                                               auth_flag_dev=i,
                                                                               auth_tag_dev=auth_tag_dev,
                                                                               enc_flag_dev=None,
                                                                               enc_block_dev=enc_block_dev,
                                                                               enc_tag_dev1=enc_tag_dev1,
                                                                               enc_tag_dev2=enc_tag_dev2,
                                                                               nonce_dev=nonce_dev)
                        
                                                if self.is_payload_valid(plaintext, pkt) and integrity:
                                                        self.security_found = True
                                                        self.deviation_found = True
                                                        self.security_policy = security_level
                                                        self.deviations_list = comb # + frame version
                                                        self.authentication_flag = i
                                                        if wrong_standard:
                                                                self.deviations_list = self.deviations_list + ('dev18',)
                                                        return True

                                else:
                                        
                                        integrity, plaintext = AES_CCM(pay,
                                                                     key,
                                                                     security_level,
                                                                     frame_counter,
                                                                     srcaddr64,
                                                                     encrypt=False,
                                                                     header=head,
                                                                     auth_flag_dev=None,
                                                                     auth_tag_dev=auth_tag_dev,
                                                                     enc_flag_dev=None,
                                                                     enc_block_dev=enc_block_dev,
                                                                     enc_tag_dev1=enc_tag_dev1,
                                                                     enc_tag_dev2=enc_tag_dev2,
                                                                     nonce_dev=nonce_dev)

                                        if self.is_payload_valid(plaintext, pkt) and integrity:
                                                self.security_found = True
                                                self.deviation_found = True
                                                self.security_policy = security_level
                                                self.deviations_list = comb # + frame version
                                                if wrong_standard:
                                                        self.deviations_list = self.deviations_list + ('dev18',)
                                                return True
                                        
                print 'Deviation not found'

                return False



        def guess_security(self, trans, pkt, key, frame_ver):
                

                for p in pkt:

                        if frame_ver == 1:
                                result = self.guess_security_2006(trans, p, key, frame_ver)
                                
                                if result == True:
                                        break
                        else:
                                result = self.guess_security_2003(trans, p, key, frame_ver)
                                
                                if result == True:
                                        break


        def guess_security_2003(self, trans, pkt, key, frame_ver):
                

                p = pkt[Dot15d4FCS]

                if p.payload.payload.__class__ != Dot15d4AuxSecurityHeader2003:                
                        p.show()
                        print "Malformatted secured packet 1 "
                        return False

                if p.payload.payload.payload != None:
        
                        # Retrieve Payload
                        pay = str(p.payload.payload.payload)
                        
                        # Look for authentication only policy (security level from 1 to 3)
                        try:
                                for security_level in range(1,5):
                                        if self.is_payload_valid(pay[:4*pow(2,security_level-1)], pkt):
                                                print('Authentication only policy, not handled yet')
                                                return False
                        except:
                                pass
                                        
                        # Look for AES-CTR and AES-CCM security policy
                        if p.fcf_srcaddrmode != 3:  
            
                                # Extended src short address not present 
                                # It is part of the keying material used to secure the frame
                                # See if we could have retrieved it during the scan
            
                                srcaddr64 = trans.originator.addr64
                
                        else:
                                
                                srcaddr64 = p.src_addr

        
                        if srcaddr64 == None:
                                print "Could not retrieve the extended src address needed to unsecure the frame"
                                return False

                        # Retrieve Header
                        if p.__class__ == Dot15d4FCS:
                                head = p.copy()
                                head.payload.payload.payload = ''
                                head = str(head)[:-2] # remove FCS

                        key = key[2:]  # remove '0x'

                        frame_counter = p.sec_framecounter
                        key_seq_counter = p.sec_keyseqcounter

                        # AES-CTR (security level 4)
                        plaintext = scapy.crypto.AESCCMDot15d4.AES_CTR(pay, key, frame_counter, srcaddr64, key_seq_counter)

                        if self.is_payload_valid(plaintext, pkt):
                                print "Security found"
                                self.security_found=True
                                self.security_policy = 4 # CTR
                                return True

                        # AES-CCM (security level from 5 to 7)
                        for security_level in range(5,8):
                                integrity, plaintext = scapy.crypto.AESCCMDot15d4.AES_CCM(pay, key, security_level, frame_counter, srcaddr64, encrypt=False, keyseqcounter=key_seq_counter, header=head)
                                
                                if integrity and self.is_payload_valid(plaintext, pkt):
                                        print "Security found"
                                        self.security_found = True
                                        self.security_policy = security_level
                                        return True
                        
                        # If here, security could not have been retrieved
                        print "Security not found"
                        self.security_found = False
                        return False
                else:
                
                        print "Malformatted secured packet 2 "
                        return False

                                

        def guess_security_2006(self, trans, pkt, key, frame_ver):


                p = pkt[Dot15d4FCS]

                if p.payload.payload.__class__ != Dot15d4AuxSecurityHeader:
                        p.show()
                        print "Malformatted secured packet 1 "
                        return False

                if p.payload.payload.payload != None:
        
                        if p.fcf_srcaddrmode != 3:  
            
                                # Extended src short address not present 
                                # It is part of the keying material used to secure the frame
                                # See if we could have retrieved it during the scan
            
                                srcaddr64 = trans.originator.addr64
                
                        else:
                                
                                srcaddr64 = p.src_addr

        
                        if srcaddr64 == None:
                                print "Could not retrieve the extended src address needed to unsecure the frame"
                                return False

                        # Retrieve Payload
                        pay = str(p.payload.payload.payload)
        
                        # Retrieve Header
                        if p.__class__ == Dot15d4FCS:
                                head = p.copy()
                                head.payload.payload.payload = ''
                                head = str(head)[:-2] # remove FCS

                        # Retrieve the security level and the frame counter
                        sec_level = p.sec_sc_seclevel
                        frame_counter = p.sec_framecounter

                        encrypt = False # Decrypt

                        key = key[2:]  # remove '0x'

                        integrity, plaintext = scapy.crypto.AESCCMDot15d4.AES_CCM(pay, key, sec_level, frame_counter, srcaddr64, encrypt, header=head)

                        if integrity and self.is_payload_valid(plaintext, pkt):
                                print "Security found"
                                self.security_found=True
                                return True

                        else:
                                print "MIC CALCULATION FAILED"
                                self.security_found=False
                                return False
        
                else:

                        print "Malformatted secured packet 2 "
                        return False

