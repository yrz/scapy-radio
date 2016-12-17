from scapy.all import *

#############
# config.py
#############


# Method used by the scanner to detect sixlowpan protocol! As sixlowpan_detection, user can define his own method to detect other protocols
# Arguments shall be the decrypted payload (string) and the original pkt as it has been captured (scapy Packet object)
def sixlowpan_detection(payload, pkt):

    p = pkt.copy()

    if not Dot15d4FCS in p:
        return False

    if not Dot15d4Data in p:
        return False

    p = p[Dot15d4FCS]

    
    try:
        p[Dot15d4Data].payload= SixLoWPAN(payload, _underlayer=p[Dot15d4Data])

    except:
        return False

    pkt = p

    if 1:
    
            if SixLoWPAN in pkt:

                if isinstance(pkt[SixLoWPAN].payload, LoWPANMesh):

                    if isinstance(pkt[LoWPANMesh].payload, LoWPAN_IPHC):

                        if pkt[LoWPAN_IPHC].nextHeader in [6,17,58]:
                            # consider it is a sixlowpan pkt
                            return True

                    elif isinstance(pkt[LoWPANMesh].payload, LoWPANUncompressedIPv6):

                        if pkt[LoWPANUncompressedIPv6].version == 6:
                                # consider it is a sixlowpan pkt
                                return True


                    elif isinstance(pkt[LoWPANMesh].payload, LoWPANFragmentationFirst):

                        if isinstance(pkt[LoWPANFragmentationFirst].payload, LoWPAN_IPHC):

                            if pkt[LoWPAN_IPHC].nextHeader in [6,17,58]:
                                # consider it is a sixlowpan pkt
                                return True

                            elif str(pkt[LoWPANFragmentationFirst].payload)[0] == '\x41': #IPv6

                                if (str(pkt[LoWPANFragmentationFirst].payload)[1] >> 4) == 6:
                                    # consider it is a sixlowpan pkt
                                    return True
                                        
                    elif isinstance(pkt[LoWPANMesh].payload, LoWPANFragmentationSubsequent):
                        # Address not present in this kind of packet
                        pass

                    elif isinstance(pkt[LoWPANMesh].payload, LoWPANBroadcast):

                        if isinstance(pkt[LoWPANBroadcast].payload, LoWPAN_IPHC):

                            if pkt[LoWPAN_IPHC].nextHeader in [6,17,58]:
                                # consider it is a sixlowpan pkt
                                return True

                        elif isinstance(pkt[LoWPANBroadcast].payload, LoWPANUncompressedIPv6):

                            if pkt[LoWPANUncompressedIPv6].version == 6:
                                # consider it is a sixlowpan pkt
                                return True

                        elif isinstance(pkt[LoWPANBroadcast].payload, LoWPANFragmentationFirst):

                            if isinstance(pkt[LoWPANFragmentationFirst].payload, LoWPAN_IPHC):

                                if pkt[LoWPAN_IPHC].nextHeader in [6,17,58]:
                                    # consider it is a sixlowpan pkt
                                    return True

                            elif str(pkt[LoWPANFragmentationFirst].payload)[0] == '\x41': #IPv6

                                if (str(pkt[LoWPANFragmentationFirst].payload)[1] >> 4) == 6:
                                    # consider it is a sixlowpan pkt
                                    return True
                                    
                        elif isinstance(pkt[LoWPANBroadcast].payload, LoWPANFragmentationSubsequent):
                            # Address not present in this kind of pkt
                            pass

                elif isinstance(pkt[SixLoWPAN].payload, LoWPANUncompressedIPv6):

                    if pkt[LoWPANUncompressedIPv6].version == 6:
                        # consider it is a sixlowpan pkt
                        return True

                elif isinstance(pkt[SixLoWPAN].payload, LoWPANFragmentationFirst):
                    
                    if isinstance(pkt[LoWPANFragmentationFirst].payload, LoWPAN_IPHC):
                        
                        if pkt[LoWPAN_IPHC].nextHeader in [6,17,58]:
                            # consider it is a sixlowpan pkt
                            return True

                    elif str(pkt[LoWPANFragmentationFirst].payload)[0] == '\x41': #IPv6

                        if (str(pkt[LoWPANFragmentationFirst].payload)[1] >> 4) == 6:
                            # consider it is a sixlowpan pkt
                            return True
                            

                elif isinstance(pkt[SixLoWPAN].payload, LoWPANFragmentationSubsequent):
                    # Address not present in this kind of pkt
                    pass

                elif isinstance(pkt[SixLoWPAN].payload, LoWPAN_IPHC):                        
                            
                    if pkt[LoWPAN_IPHC].nextHeader in [6,17,58]:
                        # consider it is a sixlowpan pkt
                        return True

                else:
                    # Not a sixlowpan packet
                    pass

    return False


class SecConf(ConfClass):

    entropy = 1
    
    max_deviations = 1


    # AES CTR deviations
    ctr_deviations = {
        
        # (Sec_level) Nonce is formatted as a 2006 nonce (with security level 4)
        'dev1' : 0,

        # (Flag) Flag is not set according to the CTR transformation
        # specified in the 802.15.4 specification
        'dev2' : 0,

        # (Counter) The first block counter used to compute the first encrypted block is not 0x0000 but 0x0001
        'dev3' : 0, 
    }

    # AES-CCM deviations
    ccm_deviations = {

        # (sec_dev) 2003 trame using 2006 nonce
        'dev4' : 0,

        # (auth_flag_dev) Input authentication flag is not set according to the CCM (or CCM*) specification
        'dev5' : 0, 

        # (auth_tag_dev) Authentication tag T is obtained by ommiting all but the rightmost M octets of the
        # last X computed block (rather than the leftmost M octets)
        'dev6' : 0,

        # (enc_flag_dev) Input encryption flag is not set according to the CCM (or CCM*) specification
        'dev7' : 0,

        # (enc_block_dev) Block counter 0x0000 is used to encrypt the first data block rather than 0x0001
        'dev8' : 0,

        # (enc_tag_dev1) The last Ai block is used to compute the S0 encryption block
        # (rather that the first A0 block)
        'dev9' : 0,

        # (enc_tag_dev2) The second A1 block is used to compute the S0 encryption block
        # (rather that the first A0 block)
        'dev10' : 0,
    }

    # AES-CCM* deviations    
    ccm_star_deviations = {

        # (auth_flag_dev) Input authentication flag is not set according to the CCM (or CCM*) specification
        'dev11' : 0,

        # (auth_tag_dev) Authentication tag T is obtained by ommiting all but the rightmost M octets of the
        # last X computed block (rather than the leftmost M octets)
        'dev12' : 0,

        # (enc_flag_dev) Input encryption flag is not set according to the CCM (or CCM*) specification
        'dev13' : 0,

        # (enc_block_dev) Block counter 0x0000 is used to encrypt the first data block rather than 0x0001
        'dev14' : 0,

        # (enc_tag_dev1) The last Ai block is used to compute the S0 encryption block
        # (rather that the first A0 block)        
        'dev15' : 0,

        # (enc_tag_dev2) The second A1 block is used to compute the S0 encryption block
        # (rather that the first A0 block)
        'dev16' : 0,

        # (nonce_dev) Nonce deviation for 2006 frame using 2003 nonce (with keyseqcounter null)
        'dev17' : 0,
    }
     

    # Constructor specific deviations
    constructor_deviations = {

        # XBEE S1: 2003 frame secured with 2006 policy (ENC only)
        'xbee' : 1,

        }
    
    # Here user is invited to enter string to be detected in unsecured frame
    # User is advised to not provide single character as a string to detect
    # Exemple : string_to_detect = ["\x12\x34\x56", "Hello"]
    strings_to_detect = ['ALIVE']

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


for k, v in security_conf.constructor_deviations.items():
    if v != 1:
        del security_conf.constructor_deviations[k]
security_conf.constructor_deviations = list(security_conf.constructor_deviations)
    
