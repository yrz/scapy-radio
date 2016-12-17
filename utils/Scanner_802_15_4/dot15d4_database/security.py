from scapy.all import *
from entropy import *
from scapy.crypto.AESCCMDot15d4 import *
from config import *
import json

class SecurityFeatures(object):

        valid_attr = {
                "security_found" : lambda x: x in [0,1],
                "deviation_found" : lambda x: x in [0,1],
                "security_policy" : lambda x: x in [i for i in range(1,8)],
                "deviations_list" : lambda x : isinstance(x, dict),
                "key"             : lambda x : True,
        }

        def __init__(self, **kwargs):

                self.security_found = False

                for k,v in kwargs.iteritems():
                        self.__setattr__(k,v)

        def __getattr__(self, attr):
                return self.__dict__.get(attr,None)

        def __setattr__(self, attr, val):
                if attr in self.valid_attr and self.valid_attr[attr](val):
                        self.__dict__[attr] = val

        def get_dict(self):

                js = {}
                
                for k,v in self.__dict__.iteritems():

                        if self.valid_attr.has_key(k):
                                js[k] = v

                return js

                
        def show(self, opt=''):
            
            print "%sSecurity Features" % opt
            
            for k,v in self.__dict__.iteritems():
                if k == 'deviations_list':
                        print '%s %s = %s' % (opt, k,v)
                elif k == 'key':
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


        def guess_deviation(self, trans, pkt, frame_ver):

                for p in pkt:

                        if frame_ver: # 2006
                                result = self.guess_deviation_2006(trans, p, frame_ver)
                                

                        else: # 2003
                                result = self.guess_deviation_2003(trans, p, frame_ver)

                        if result == True:
                                break

        


        def guess_deviation_2003(self, trans, pkt, frame_ver):
                

                if security_conf.max_deviations == 0:
                        return False

                # Note : Authentication only policy (CBC-MAC) is not handled yet 

                dev_constructor = security_conf.constructor_deviations
                dev_ctr = security_conf.ctr_deviations
                dev_ccm = security_conf.ccm_deviations

                # No deviations to look for : either the max_deviation is 0 or the lists of 
                # deviations to check is empty!
                if not dev_ctr and not dev_ccm and not dev_constructor:
                        print 'No deviation to look for'
                        return False

                p = pkt[Dot15d4FCS]

                if p.payload != None:
        
                        # Retrieve Payload
                        pay = p.payload.get_payload_fields()
                       
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
                                self.security_found = False
                                return False

                        # Retrieve Header
                        head = p.get_mhr() + p.payload.get_nonpayload_fields()

                        key = self.key

                        if key == None:
                                print "Encryption key missing!"
                                return False
                        
                        key = key[2:]  # remove '0x'

                        frame_counter = p.aux_sec_header_2003.sec_framecounter
                        key_seq_counter = p.aux_sec_header_2003.sec_keyseqcounter

                else:
                        print 'Malformated packet'
                        return False


                
                devs = {}
                
                # Handle constructor deviations
                if 'xbee' in dev_constructor:

                        devs['xbee'] = True

                        plaintext, integrity = aes_ccm_star_inverse(pay, head, key, 4, frame_counter,srcaddr64, **devs)

                        if integrity and self.is_payload_valid(plaintext, pkt):
                                self.security_found = True
                                self.deviation_found = True
                                self.security_policy = 1
                                self.deviations_list = devs
                                return True

                        

                # Handle CTR deviations

                # Listing every combination of deviation (depending on the max_deviations value) 
                deviation_comb = []

                for comb in range(1, security_conf.max_deviations + 1):

                        tmp = []
                        c = itertools.combinations(dev_ctr, comb)

                        for dev in c:
                                tmp.append(dev)
                
                        deviation_comb.append(tmp)

                # Looking for every combination of deviations (CTR) we listed above
                for c in deviation_comb:

                 devs = {}

                 for comb in c:

                        if 'dev1' in comb:
                                devs['Sec_level'] = True
                                        
                        if 'dev3' in comb:
                                devs['Counter'] = True
                                
                        if 'dev2' in comb:

                                # Let's bruteforce the flag
                                for i in xrange(pow(2,8)):

                                        devs['Flag'] = i

                                        plaintext = aes_ctr(pay, key, frame_counter, srcaddr64, key_seq_counter, **devs)
                                        
                                        if self.is_payload_valid(plaintext, pkt):
                                                self.security_found = True
                                                self.deviation_found = True
                                                self.security_policy = 4
                                                self.deviations_list = devs
                                                return True
                    
                        else: 

                                plaintext = aes_ctr(pay, key, frame_counter, srcaddr64, key_seq_counter, **devs)
                                
                                if self.is_payload_valid(plaintext, pkt):
                                        self.security_found = True
                                        self.deviation_found = True
                                        self.security_policy = 4
                                        self.deviations_list = devs
                                        return True

                # Handle CCM deviations

                # Listing every combination of deviation (depending on the max_deviations value) 
                deviation_comb = []

                for comb in range(1, security_conf.max_deviations + 1):

                        tmp = []
                        c = itertools.combinations(dev_ccm, comb)

                        for dev in c:
                                tmp.append(dev)
                
                        deviation_comb.append(tmp)


                # Looking for every combination of deviations (CTR) we listed above
                for security_level in range(5, 8):

                  for c in deviation_comb:

                    devs = {}

                    for comb in c:

                        if 'dev4' in comb:
                                 devs['sec_dev'] = True
                    
                        if 'dev6' in comb:
                                devs['auth_tag_dev'] = True

                        if 'dev8' in comb:
                                devs['enc_block_dev'] = True

                        if 'dev9' in comb:
                                devs['enc_tag_dev1'] = True

                        if 'dev10' in comb:
                                devs['enc_tag_dev2'] = True
                
                        if 'dev7' in comb:
                    
                                for i in xrange(pow(2,8)):

                                        devs['enc_flag_dev'] = i
                                        
                                        if 'dev5'in comb:

                                                for j in xrange(pow(2,8)):
                                
                                                        devs['auth_flag_dev'] = j

                                                        plaintext, integrity = aes_ccm_inverse(pay, head, key, security_level, frame_counter, srcaddr64, key_seq_counter, **devs)
                                                
                                                        if integrity and self.is_payload_valid(plaintext, pkt):
                                                                self.security_found = True
                                                                self.deviation_found = True
                                                                self.security_policy = security_level
                                                                self.deviations_list = devs
                                                                return True

                                        else:

                                                plaintext, integrity = aes_ccm_inverse(pay, head, key, security_level, frame_counter, srcaddr64, key_seq_counter, **devs)

                                                if integrity and self.is_payload_valid(plaintext, pkt):
                                                        self.security_found = True
                                                        self.deviation_found = True
                                                        self.security_policy = security_level
                                                        self.deviations_list = devs
                                                        return True

                        elif 'dev5' in comb:

                                for i in xrange(pow(2,8)):

                                        devs['auth_flag_dev'] = i

                                        plaintext, integrity = aes_ccm_inverse(pay, head, key, security_level, frame_counter, srcaddr64, key_seq_counter, **devs)                        
                        
                                        if integrity and self.is_payload_valid(plaintext, pkt):
                                                self.security_found = True
                                                self.deviation_found = True
                                                self.security_policy = security_level
                                                self.deviations_list = devs
                                                return True

                        else:

                                plaintext, integrity = aes_ccm_inverse(pay, head, key, security_level, frame_counter, srcaddr64, key_seq_counter, **devs)

                                if integrity and self.is_payload_valid(plaintext, pkt):
                                        self.security_found = True
                                        self.deviation_found = True
                                        self.security_policy = security_level
                                        self.deviations_list = devs
                                        return True


                print 'Deviation not found' 
                return False



        def guess_deviation_2006(self, trans, pkt, frame_ver):


                if security_conf.max_deviations == 0:
                        return False

                dev_ccm_star = security_conf.ccm_star_deviations

                # No deviations to look for : either the max_deviation is 0 or the list of 
                # deviations to check is empty!
                if not dev_ccm_star:
                        print 'No deviation to look for'
                        return False

                p = pkt[Dot15d4FCS]

                if p.payload != None:
        
                        if p.fcf_srcaddrmode != 3:
            
                                # Extended src short address not present 
                                # It is part of the keying material used to secure the frame
                                # See if we could have retrieved it during the scan
            
                                srcaddr64 = trans.originator.addr64
                
                        else:
                                
                                srcaddr64 = p.src_addr

        
                        if srcaddr64 == None:
                                print "Could not retrieve the extended src address needed to unsecure the frame"
                                self.security_found = False
                                return False

                        # Retrieve Payload
                        pay = p.payload.get_payload_fields()
        
                        # Retrieve Header
                        head = p.get_mhr() + p.payload.get_nonpayload_fields()
                                
                        # Retrieve the security level and the frame counter
                        frame_counter = p.aux_sec_header.sec_framecounter

                        key = self.key

                        if key == None:
                                print 'Encryption key missing! '
                                return False
                        
                        key = key[2:]  # remove '0x'


                else:
                        print 'Malformated Packet'
                        return False

                # Listing every combination of deviation (depending on the max_deviations value) 
                deviation_comb = []

                for comb in range(1, security_conf.max_deviations + 1):

                        tmp = []
                        c = itertools.combinations(dev_ccm_star, comb)

                        for dev in c:
                                tmp.append(dev)
                
                        deviation_comb.append(tmp)


                for security_level in range(1,8):

                       # Looking for every combination of deviations we listed above
                       for c in deviation_comb:

                        devs = {}
                        
                        for comb in c:

                                if 'dev17' in comb:
                                        devs['nonce_dev'] = True
                                        
                                if 'dev12' in comb:
                                        devs['auth_tag_dev'] = True
                                
                                if 'dev14' in  comb:
                                        devs['enc_block_dev'] = True
            
                                if 'dev15' in comb:
                                        devs['enc_tag_dev1'] = True
        
                                if 'dev16' in comb:
                                        devs['enc_tag_dev2'] = True
                        
                                if 'dev13' in comb:
                                        
                                        # Let's bruteforce the flag octet for encryption
                                        for i in xrange(pow(2,8)):

                                                devs['enc_flag_dev'] = i
                                                
                                                if 'dev11' in comb:

                                                        # Let's bruteforce the flag octet for authentication too
                                                        for j in xrange(pow(2,8)):

                                                                devs['auth_flag_dev'] = j
                                                                
                                                                plaintext, integrity = aes_ccm_star_inverse(pay, head, key,
                                                                                                            security_level,
                                                                                                            frame_counter,
                                                                                                            srcaddr64,
                                                                                                            **devs)

                                                                if self.is_payload_valid(plaintext, pkt) and integrity:
                                                                        self.security_found = True
                                                                        self.deviation_found = True
                                                                        self.security_policy = security_level
                                                                        self.deviations_list = devs
                                                                        return True
                                                else:
                                                        
                                                        plaintext, integrity = aes_ccm_star_inverse(pay,
                                                                                                   head,
                                                                                                   key,
                                                                                                   security_level,
                                                                                                   frame_counter,
                                                                                                   srcaddr64,
                                                                                                   **devs)

                                                        if self.is_payload_valid(plaintext, pkt) and integrity:
                                                                self.security_found = True
                                                                self.deviation_found = True
                                                                self.security_policy = security_level
                                                                self.deviations_list = devs
                                                                return True
                                        
                                elif 'dev11' in comb:
                                        
                                        for i in xrange(pow(2,8)):

                                                devs['auth_flag_dev'] = i

                                                plaintext, integrity = aes_ccm_star_inverse(pay,
                                                                                            head,
                                                                                            key,
                                                                                            security_level,
                                                                                            frame_counter,
                                                                                            srcaddr64,
                                                                                            **devs)
                        
                                                if self.is_payload_valid(plaintext, pkt) and integrity:
                                                        self.security_found = True
                                                        self.deviation_found = True
                                                        self.security_policy = security_level
                                                        self.deviations_list = devs
                                                        return True

                                else:
                                        
                                        plaintext, integrity = aes_ccm_star_inverse(pay,
                                                                                   head,
                                                                                   key,
                                                                                   security_level,
                                                                                   frame_counter,
                                                                                   srcaddr64,
                                                                                   **devs)

                                        if integrity and self.is_payload_valid(plaintext, pkt):
                                                self.security_found = True
                                                self.deviation_found = True
                                                self.security_policy = security_level
                                                self.deviations_list = devs
                                                return True
                                        
                print 'Deviation not found'
                return False



        def guess_security(self, trans, pkt, frame_ver):
                
                for p in pkt:

                        if frame_ver == 1:
                                result = self.guess_security_2006(trans, p, frame_ver)
                                
                                if result == True:
                                        break
                        else:
                                result = self.guess_security_2003(trans, p, frame_ver)
                                
                                if result == True:
                                        break


        def guess_security_2003(self, trans, pkt, frame_ver):
                

                p = pkt[Dot15d4FCS]

                if p.payload != None:
        
                        # Retrieve Payload
                        pay = p.payload.get_payload_fields()
                        
                        # Look for authentication only policy (security level from 1 to 3)
                        try:
                                for M in [4,8,16]:
                                        if self.is_payload_valid(pay[:-M], pkt):
                                                #TODO
                                                self.security_found=False
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
                                self.security_found = False
                                return False

                        # Retrieve Header
                        head = p.get_mhr() + p.payload.get_nonpayload_fields()
                
                        key = self.key

                        if key == None:
                                print "Encryption key missing!"
                                return False

                        key = key[2:]  # remove '0x'

                        frame_counter = p.aux_sec_header_2003.sec_framecounter
                        key_seq_counter = p.aux_sec_header_2003.sec_keyseqcounter

                        # AES-CTR (security level 1)
                        plaintext = aes_ctr(pay, key, frame_counter, srcaddr64, key_seq_counter)

                        if self.is_payload_valid(plaintext, pkt):
                                print "Security found"
                                self.security_found=True
                                self.security_policy = 4 # CTR
                                return True

                        # AES-CCM (security level from 2 to 4)
                        for security_level in [2,3,4]:

                                plaintext, integrity = aes_ccm_inverse(pay, head, key, security_level, frame_counter, srcaddr64, key_seq_counter)
                                
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

                                

        def guess_security_2006(self, trans, pkt, frame_ver):

                p = pkt[Dot15d4FCS]

                if p.payload != None:
        
                        if p.fcf_srcaddrmode != 3:  
            
                                # Extended src short address not present 
                                # It is part of the keying material used to secure the frame
                                # See if we could have retrieved it during the scan
            
                                srcaddr64 = trans.originator.addr64
                
                        else:
                                
                                srcaddr64 = p.src_addr

        
                        if srcaddr64 == None:
                                print "Could not retrieve the extended src address needed to unsecure the frame"
                                self.security_found = False
                                return False

                        # Retrieve Payload
                        pay = p.payload.get_payload_fields()
        
                        # Retrieve Header
                        head = p.get_mhr() + p.payload.get_nonpayload_fields()

                        # Retrieve the security level and the frame counter
                        sec_level = p.aux_sec_header.sec_sc_seclevel
                        frame_counter = p.aux_sec_header.sec_framecounter

                        key = self.key

                        if key == None:
                                print 'Encryption key missing!'
                                return False
                        
                        key = key[2:]  # remove '0x'

                        plaintext, integrity = aes_ccm_star_inverse(pay, head, key, sec_level, frame_counter, srcaddr64)

                        if integrity and self.is_payload_valid(plaintext, pkt):
                                print "Security found"
                                self.security_found=True
                                self.security_policy = sec_level
                                return True

                        else:
                                print "MIC CALCULATION FAILED"
                                self.security_found=False
                                return False
        
                else:

                        print "Malformatted secured packet 2 "
                        return False
