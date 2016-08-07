from scapy.all import *

#############
# config.py
#############


# Method used by the scanner to detect sixlowpan protocol! As sixlowpan_detection, user can define his own method to detect other protocols
# Arguments shall be the decrypted payload (string) and the original pkt as it has been captured (scapy Packet object)
# For sixlowpan detection, the only packet which can be detected (for the moment) are IPv6 uncompressed packets and IPHC packets!
def sixlowpan_detection(payload, pkt):

    '''
    # SixLoWPAN Frag1 packet ? 
    if (ord(payload[0]) >> 3) == 0x18:

        # Check if datagram_size is greater than 1280!
        if ((ord(payload[0]) & 0x7) == 5 and ord(payload[1]) == 0) or (ord(payload[0]) & 0x7) < 5:
                                        
            # Next header is either the No compressed LoWPAN_IPv6 header or the LoWPAN_IPHC
            if (ord(payload[4]) == 0x41) or ((ord(payload[4]) >> 5) == 0x3):
                print 'SixLoWPAN FRAG1 packet'
                return True

    # SixLoWPAN FragN packet ? 
    elif (ord(payload[0]) >> 3) == 0x1c:
        # Check if datagram_size is greater than 1280!
        if ((ord(payload[0]) & 0x7) == 5 and ord(payload[1]) == 0) or (ord(payload[0]) & 0x7) < 5:
            print 'SixLoWPAN FragN packet'
            return True
    '''

    p = pkt.copy()

    if not Dot15d4FCS in p:
        return False

    if not Dot15d4Data in p:
        return False

    p = p[Dot15d4FCS]

    p[Dot15d4Data].payload=''
    
    if not p.fcf_security:
        return False

    # Disabling security
    p.fcf_security=0
    
    # SixLoWPAN Uncompressed IPv6 packet ?                         
    if ord(payload[0]) == 0x41:

        try:
            
            p = Dot15d4FCS(str(p / payload))  # Reconstructing unsecured packet 

            if SixLoWPAN in p:

                if IPv6 in p:
                
                    if p[IPv6].nh in [58, 6, 17] :  # ICMPv6, UDP, TCP
                    
                        _cksum = p[IPv6].payload.cksum

                        p[IPv6].payload.cksum = 0
                        
                        phdr = PseudoIPv6(src=p.sourceAddr, dst=p.destinyAddr, nh=58, uplen=len(p[IPv6].payload)) 

                        sphdr = str(phdr)

                        sicmpv6_pay = str(p[IPv6].payload)
                        
                        cksum = checksum(sphdr + sicmpv6_pay)
                        
                        if _cksum == cksum:
                            return True
        except:
            pass


    # SixLoWPAN IPHC packet ?
    elif (ord(payload[0]) >> 5) == 0x3: # Weak rule

        try:

            p = Dot15d4FCS(str(p / payload))  # Reconstructing unsecured packet 

            if SixLoWPAN in p:

                if LoWPAN_IPHC in p:
                

                    if p[LoWPAN_IPHC].nh == 0 and p[LoWPAN_IPHC].nextHeader in [58, 6, 17] :  # ICMPv6, UDP, TCP but not compressed LoWPAN_UDP 
                    
                        _cksum = p[LoWPAN_IPHC].payload.cksum

                        p[LoWPAN_IPHC].payload.cksum = 0
                        
                        phdr = PseudoIPv6(src=p.sourceAddr, dst=p.destinyAddr, nh=58, uplen=len(p[LoWPAN_IPHC].payload)) 

                        sphdr = str(phdr)

                        sicmpv6_pay = str(p[LoWPAN_IPHC].payload)
                        
                        cksum = checksum(sphdr + sicmpv6_pay)
                        
                        if _cksum == cksum:
                            #print 'SixLoWPAN IPHC Packet'
                            return True
        
 
        except:
            pass

    return False



class SecConf(ConfClass):

    entropy = 2
    
    max_deviations = 3

    ctr_deviations = {
        
        # AES CTR deviations
        'dev1' : 1,  # Nonce is the 2006 one
        'dev2' : 1,  # Flag octet is not set to 0b10000010
        'dev3' : 1,  # The first block counter is 0x0001 and not 0x0000
    }

    # AES-CCM deviations
    ccm_deviations = {

        'dev4' : 1,
        'dev5' : 0,
        'dev7' : 1,
        'dev6' : 0,
        'dev8' : 0,
        'dev9' : 0,
        'dev10' : 0,
    }

    # AES-CCM* deviations    
    ccm_star_deviations = {

        'dev11' : 1,  # Flag octet for authentication is not set to the standard's value
        'dev12' : 0,  # Auth tag deviation
        'dev13' : 1,  # Flag octet for encryption is not he good one
        'dev14' : 0,  # Enc tag deviation
        'dev15' : 0,  # TAG U deviation 1
        'dev16' : 0,  # TAG U deviation 2
        'dev17' : 0,
    }
     
    
    version_deviations = {
        # Version deviations
        'dev18' : 0,  # 2003 trame secured with a 2006 standard policy    
        'dev19' : 0,  # 2006 trame secured with a 2003 standard policy    
    }
    
    # Here user is invited to enter string to be detected in unsecured frame
    # User is advised to not provide single character as a string to detect
    # Exemple : string_to_detect = ["\x12\x34\x56", "Hello"]
    strings_to_detect = []

    # Just add your own protocol detection method! 
    protocol_to_detect = {
        'sixlowpan' : sixlowpan_detection,
    } 
    

security_conf  = SecConf()

for k, v in security_conf.ccm_star_deviations.items():
    if v != 1:
        del security_conf.ccm_star_deviations[k]
security_conf.ccm_star_deviations = list(security_conf.ccm_star_deviations)

for k, v in security_conf.ccm_deviations.items():
    if v != 1:
        del security_conf.ccm_deviations[k]
security_conf.ccm_deviations = list(security_conf.ccm_deviations)

for k, v in security_conf.ctr_deviations.items():
    if v != 1:
        del security_conf.ctr_deviations[k]
security_conf.ctr_deviations = list(security_conf.ctr_deviations)

for k, v in security_conf.version_deviations.items():
    if v != 1:
        del security_conf.version_deviations[k]
security_conf.version_deviations = list(security_conf.version_deviations)

if __name__ == '__main__':
    

    print security_conf.ccm_star_deviations
    print security_conf.ccm_deviations
    print security_conf.ctr_deviations
    print security_conf.version_deviations
