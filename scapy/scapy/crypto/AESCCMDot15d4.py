#!/usr/bin/python2
import  struct
import json

from Crypto.Cipher import AES

def xor_strings(xs, ys):
	return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

def E(key, message):
	cipher = AES.new(key)
	return cipher.encrypt(message)

def addZerosTobeDivisibleBy16(string):
	if ((len(string)/2)%16) != 0:
		for i in range(16 - (len(string)/2)%16):
			string = string + "00"
	return string


def addZerosTobeDivisibleBy162(string):
	if len(string)%16 != 0:
		for i in range(16 - len(string)%16):
			string = string + '\x00'
	return string


''' 2003 - security levels :
# 0 = None
# 1 = AES-CTR
# 2 = AES-CCM-128
# 3 = AES-CCM-64
# 4 = AES-CCM-32
# 5 = AES-CBC-MAC-128
# 6 = AES-CBC-MAC-64
# 7 = AES-CBC-MAC-32
'''

''' 
2006 security levels :
0 = None
1 = AES-CCM* (MIC-32)
2 = AES-CCM* (MIC-64)
3 = AES-CCM* (MIC-128)
4 = AES-CCM* (ENC)
5 = AES-CCM* (ENC-MIC-32)
6 = AES-CCM* (ENC-MIC-64)
7 = AES-CCM* (ENC-MIC-128)
'''

def cipherDot15d4Unsecure(text, header, key, seclevel, frame_counter, src_addr, keyseqcounter=None, **devs):

        '''
        Info: The frame version is deduced by the value of keyseqcounter (None -> 2006 / != None -> 2003) 
        Return value : Cleartext + MIC (Success or Fail)
        '''
        if keyseqcounter != None:

                if devs.has_key('xbee'):
                        #xbee deviation
                        return aes_ccm_star_inverse(text, header, key, 4, frame_counter, src_addr, **devs)
                        


                if seclevel == 1:
                        return aes_ctr(text, key, frame_counter, src_addr, keyseqcounter, **devs), True
                elif seclevel in [2,3,4]:
                        return aes_ccm_inverse(text, header, key, seclevel, frame_counter, src_addr, keyseqcounter, **devs)
                elif seclevel in [5,6,7]:
                        return text, True  #aes_cbc_mac(text, header, key, seclevel, frame_counter, src_addr, keyseqcounter, **devs)

        else:
                if seclevel in [1,2,3,4,5,6,7]:
                        return aes_ccm_star_inverse(text, header, key, seclevel, frame_counter, src_addr, **devs)



def maleabilityDot15d4(text, keystreams):

        if len(keystreams) < (len(text)/16 + (len(text)%16 and 1 or 0)):
                print "Cannot secure frame using maleability, size doesn't match"
                return text

        m = text

        Data = []
        
        while m != '':
                if len(m) < 16:
                        Data.append(m)
                        m = ''
                else:
                        Data.append(m[:16])
                        m = m[16:]

        newtext = ""

        for D,K in zip(Data, keystreams):
                Ci = xor_strings(K.decode('hex')[:len(D)], D)
                newtext += Ci

        return newtext


def cipherDot15d4Secure(text, header, key, seclevel, frame_counter, src_addr, keyseqcounter=None,  **devs):

        '''
        Info: The frame version is deduced by the value of keyseqcounter (None -> 2006 / != None -> 2003) 
        Return value : Ciphertext
        '''

        if keyseqcounter != None:
                # 2003-frame

                if devs.has_key('xbee'):
                        # Xbee s1 deviation
                        return aes_ccm_star(text, header, key, 4, frame_counter, src_addr, **devs)
                
                if seclevel == 1:
                        return aes_ctr(text, key, frame_counter, src_addr, keyseqcounter, **devs)
                elif seclevel in [2,3,4]:
                        return aes_ccm(text, header, key, seclevel, frame_counter, src_addr, keyseqcounter, **devs)
                elif seclevel in [5,6,7]:
                        return text  #aes_cbc_mac(text, header, key, seclevel, frame_counter, src_addr, keyseqcounter, **devs)
                
        else:
                # 2006-frame
                
                ''' 2006 security levels :
                # 0 = None
                # 1 = AES-CCM* (MIC-32)
                # 2 = AES-CCM* (MIC-64)
                # 3 = AES-CCM* (MIC-128)
                # 4 = AES-CCM* (ENC)
                # 5 = AES-CCM* (ENC-MIC-32)
                # 6 = AES-CCM* (ENC-MIC-64)
                # 7 = AES-CCM* (ENC-MIC-128) 
                '''
                
                if seclevel in [1,2,3,4,5,6,7]:
                        return aes_ccm_star(text, header, key, seclevel, frame_counter, src_addr, **devs)

                
def aes_ccm_star_inverse(text, header, key, seclevel, frame_counter, src_addr, **devs):

        ''' Specific implementation of inverse CCM* for 802.15.4. See IEEE Standard for Information Technologie Part 15.4 (802.15.4) '''

        '''
        Handling deviation from the standard :
        Deviation handled are : auth_flag_dev, auth_tag_dev, enc_flag_dev, enc_block_dev, enc_tag_dev1, enc_tag_dev2, nonce_dev.
        See security config file.
        '''

        auth_flag_dev = devs.get('auth_flag_dev', None)
        auth_tag_dev = devs.get('auth_tag_dev', None)
        enc_flag_dev = devs.get('enc_flag_dev', None)
        enc_block_dev = devs.get('enc_block_dev', None)
        enc_tag_dev1 = devs.get('enc_tag_dev1', None)
        enc_tag_dev2 = devs.get('enc_tag_dev2', None)
        nonce_dev = devs.get('nonce_dev', None)
        xbee_dev = devs.get('xbee', None)
        
        if not seclevel in [1,2,3,4,5,6,7]:
                return text

        sec_hex = hex(int(seclevel))
        M_id = {"0x1":4, "0x2":8, "0x3":16, "0x4":0, "0x5":4, "0x6":8, "0x7":16}
        M = M_id[sec_hex]

        ''' INPUT B.4.1 a) -> d)'''

        # B.4.2 a)
        key = key.decode('hex')

        # B.4.2 b) : Preparing the nonce

        if xbee_dev != None:
                frame_counter = struct.pack('I', frame_counter)

        else:
                frame_counter = struct.pack('>I', frame_counter)

        src_addr = struct.pack('>Q', src_addr)
        seclevel = struct.pack('B', seclevel)
        nonce = src_addr + frame_counter + seclevel

        # DEVIATION: Nonce deviation for 2006 frame using 2003 nonce ( with keyseqcounter null)
        if nonce_dev:
                nonce = src_addr + frame_counter + struct.pack('B', 0)

        # B.4.2 c) and B.4.2 d)
        if int(sec_hex,16) >= 4:
                # (Decryption + Authentication) or (Decryption only) 
                a = header
                c = text
        else:
                # Authentication only
                a = header + text[:-M] 
                c = text[-M:]

        

        ''' DECRYPTION TRANSFORMATION B.4.1.1 a) -> d)'''

        # B.4.2.1 a) : Parse the message c as C||U
        if int(sec_hex,16) != 4:
                C = c[:-M]
                U = c[-M:]
        else:
                # Encryption only
                C = c
                U = ''
        
        # B.4.2.1 b)
        CipherTextData = addZerosTobeDivisibleBy162(C)

        # B.4.2.1 c)

        ''' encryption transformation in B.4.1.3, with as inputs CipherTextData and U.  +++ '''
        
        # B.4.1.3 a): Form the 1-octet Flags fields (Flags = Reserved||Reserved||0||f(L))
        L = 2  # In the scope of 802.15.4
        Flags = struct.pack('B', L-1)

        # DEVIATION: Input flag 'Flags' is not set according to the CCM* specification
        if enc_flag_dev != None:
                Flags = struct.pack('B', enc_flag_dev)
        
        # B.4.1.3 b)
        A = []
        for i in xrange(len(CipherTextData)/16 + 1):
                A.append(Flags + nonce + struct.pack('>H', i))

        # B.4.1.3 c)
        MData = []
        while CipherTextData != '':
                MData.append(CipherTextData[:16])
                CipherTextData = CipherTextData[16:]
        
        # B.4.1.3 d)
        Plaintext = ''
        for i, Mi in enumerate(MData):

                # DEVIATION : Block A0 is used as a first block for encryption
                if enc_block_dev != None:
                        Ci = xor_strings(E(key, A[i]), Mi)

                else:
                        Ci = xor_strings(E(key, A[i+1]), Mi)

		Plaintext = Plaintext + Ci

        # B.4.1.3 e) : Ommiting all but the leftmost l(C) octets of Plaintext
        Plaintext = Plaintext[:len(C)]

        # B.4.1.3 f):
        S0 = E(key, A[0])

        # DEVIATION: The last Ai block is used to compute the S0 encryption block (rather that the first A0 block)
        if enc_tag_dev1 == True:
                S0 = E(key, A[-1])

        # DEVIATION: The second A1 block is used to compute the S0 encryption block (rather that the first A0 block)
        elif enc_tag_dev2 == True:
                A1 = Flags + nonce + struct.pack('>H', 1)
                S0 = E(key, A1)
        
        # B.4.1.3 g)
        T = xor_strings(S0[:M], U)

        ''' encryption transformation in B.4.1.3, with as inputs CipherTextData and U.  --- '''        

        # B.4.2.1 d)
        m = Plaintext


        ''' AUTHENTICATION CHECKING TRANSFORMATION B.4.2.2 a) -> c) '''

        if M != 0:

                # B.4.2.2 a)
                
                ''' INPUT TRANSFORMATION B.4.1.1 +++ '''
                 
                # B.4.1.1 a)
                if a != '':
                        La = struct.pack('>H', len(a))
                else:
                        La = ''
                         
                # B.4.1.1 b)
                La_a = La + a
                # B.4.1.1 c)
                AddAuthData = addZerosTobeDivisibleBy162(La_a)
                # B.4.1.1 d)
                PlaintextData = addZerosTobeDivisibleBy162(m)
                # B.4.1.1 e)
                AuthData = AddAuthData + PlaintextData
                 
                ''' INPUT TRANSFORMATION B.4.1.1 --- '''

                # B.4.2.2 b)

                ''' AUTHENTICATION TRANSFORMATION B.4.1.2 with as input AuthData +++ '''
                
                # B.4.1.2 a) Form the 1-octet Flags fields (Flags = Reserved||Adata||f(M)||g(L))
                L = 2  # In the scope of 802.15.4
                Flags = struct.pack('B', (1 << 6) + ((M-2)/2 << 3) + (L-1))

                # DEVIATION: Input flag 'Flags' is not set according to the CCM* specification
                if auth_flag_dev != None:
                        Flags = struct.pack('B', auth_flag_dev)

                # B.4.1.2 b) : Form the 16-octets B0 string.
                B = []
                B.append(Flags + nonce + struct.pack('>H', len(m)))

                # B.4.1.2 c) : Parse AuthData as B1||B2||...||Bt where Bi is a 16-octets string.
                while AuthData != '':
                        B.append(AuthData[:16])
                        AuthData = AuthData[16:]
                
                # B.4.1.2 d): Compute the CBC-MAC value
                X = []
                X.append(struct.pack('16x'))  # Null IV
                for i in range(len(B)):
                        XxorB = xor_strings(X[i], B[i])
                        X.append(E(key, XxorB))
                CBC_MAC = X[-1]

                # B.4.1.2 e) Keep the leftmost M octets of the CBC-MAC
                MACTag = CBC_MAC[:M]

                # DEVIATION: T is obtained by ommiting all but the rightmost M octets of the
                # last X computed block (rather than the leftmost M octets)
                if auth_tag_dev == True:  
                    MACTag = CBC_MAC[-M:]


                
                ''' AUTHENTICATION TRANSFORMATION B.4.1.2 with as input AuthData --- '''
                

        else:
                MACTag = ''
                
        
        if Plaintext == '':
                Plaintext = text[:-M]

        return Plaintext, (MACTag == T)  # B.4.2.2 c)



                
def aes_ccm_star(text, header, key, seclevel, frame_counter, src_addr, **devs):

        ''' Specific implementation of CCM* for 802.15.4. See IEEE Standard for Information Technologie Part 15.4 (802.15.4)  '''

        ''' 
        Handling deviation from the standard :
        Deviation handled are : auth_flag_dev, auth_tag_dev, enc_flag_dev, enc_block_dev, enc_tag_dev1, enc_tag_dev2, nonce_dev.
        See security config file.
        '''

        auth_flag_dev = devs.get('auth_flag_dev', None)
        auth_tag_dev = devs.get('auth_tag_dev', None)
        enc_flag_dev = devs.get('enc_flag_dev', None)
        enc_block_dev = devs.get('enc_block_dev', None)
        enc_tag_dev1 = devs.get('enc_tag_dev1', None)
        enc_tag_dev2 = devs.get('enc_tag_dev2', None)
        nonce_dev = devs.get('nonce_dev', None)
        xbee_dev =  devs.get('xbee', None)
        
        if not seclevel in [1,2,3,4,5,6,7]:
                return text

        sec_hex = hex(int(seclevel))
        M_id = {"0x1":4, "0x2":8, "0x3":16, "0x4":0, "0x5":4, "0x6":8, "0x7":16}
        M = M_id[sec_hex]

        ''' INPUT B.4.1 a) -> d)'''

        # B.4.1 a)
        key = key.decode('hex')

        # B.4.1 b) : Preparing the nonce
        if xbee_dev != None:
                frame_counter = struct.pack('I', frame_counter)
        else:
                frame_counter = struct.pack('>I', frame_counter)
                
        src_addr = struct.pack('>Q', src_addr)
        seclevel = struct.pack('B', seclevel)
        nonce = src_addr + frame_counter + seclevel

        # DEVIATION: Nonce deviation for 2006 frame using 2003 nonce ( with keyseqcounter null)
        if nonce_dev:
                nonce = src_addr + frame_counter + struct.pack('B', 0)
        
        # B.4.1 c) and B.4.1 d)
        if int(sec_hex,16) < 4:
                # Authentication only
                a = header + text
                m = ''
        elif int(sec_hex,16) == 4:
                # Encryption only
                a = ''
                m = text
        else:
                # Authentication + encryption
                a = header
                m = text

        L = 2  # In the scope of 802.15.4
                
        ''' INPUT TRANSFORMATION B.4.1.1 a) -> d)'''

        # B.4.1.1 a)
        if a != '':
                La = struct.pack('>H', len(a))
        else:
                La = ''

        # B.4.1.1 b)
        La_a = La + a
        # B.4.1.1 c)
        AddAuthData = addZerosTobeDivisibleBy162(La_a)
        # B.4.1.1 d)
        PlaintextData = addZerosTobeDivisibleBy162(m)
        # B.4.1.1 e)
        AuthData = AddAuthData + PlaintextData


        ''' ** AUTHENTICATION TRANSFORMATION ** B.4.1.2 a) -> e)'''

        if La != '':

                # B.4.1.2 a) Form the 1-octet Flags fields (Flags = Reserved||Adata||f(M)||g(L))
                Flags = struct.pack('B', (1 << 6) + ((M-2)/2 << 3) + (L-1))

                # DEVIATION: Input flag 'Flags' is not set according to the CCM* specification
                if auth_flag_dev != None:
                        Flags = struct.pack('B', auth_flag_dev)

                # B.4.1.2 b) : Form the 16-octets B0 string.
                B = []
                B.append(Flags + nonce + struct.pack('>H', len(m)))

                # B.4.1.2 c) : Parse AuthData as B1||B2||...||Bt where Bi is a 16-octets string.
                while AuthData != '':
                        B.append(AuthData[:16])
                        AuthData = AuthData[16:]
                
                # B.4.1.2 d): Compute the CBC-MAC value
                X = []
                X.append(struct.pack('16x'))  # Null IV
                for i in range(len(B)):
                        XxorB = xor_strings(X[i], B[i])
                        X.append(E(key, XxorB))
                CBC_MAC = X[-1]

                # B.4.1.2 e) Keep the leftmost M octets of the CBC-MAC
                T = CBC_MAC[:M]

                # DEVIATION: T is obtained by ommiting all but the rightmost M octets of the
                # last X computed block (rather than the leftmost M octets)
                if auth_tag_dev == True:
                    T = CBC_MAC[-M:]

        else:
                        
                T = ''

                
        ''' **  ENCRYPTION TRANSFORMATION ** B.4.1.3 a) -> g) '''

        # B.4.1.3 a): Form the 1-octet Flags fields (Flags = Reserved||Reserved||0||f(L))
        Flags = struct.pack('B', L-1)

        # DEVIATION: Input flag 'Flags' is not set according to the CCM* specification
        if enc_flag_dev != None:
                Flags = struct.pack('B', enc_flag_dev)
        
        # B.4.1.3 b)
        A = []
        for i in xrange(len(PlaintextData)/16 + 1):
                A.append(Flags + nonce + struct.pack('>H', i))

        # B.4.1.3 c)
        MData = []
        while PlaintextData != '':
                MData.append(PlaintextData[:16])
                PlaintextData = PlaintextData[16:]
        
        # B.4.1.3 d)
        Ciphertext = ''
        for i, Mi in enumerate(MData):

                # DEVIATION: Block A0 is used as a first block for encryption
                if enc_block_dev != None:
                        Ci = xor_strings(E(key, A[i]), Mi)

                else:
                        Ci = xor_strings(E(key, A[i+1]), Mi)

		Ciphertext = Ciphertext + Ci

        # B.4.1.3 e) : Ommiting all but the leftmost l(m) octets of Ciphertext
        if m != '':
                Ciphertext = Ciphertext[:len(m)]
        else:
                # authentication only
                Ciphertext = text

        # B.4.1.3 f):
        S0 = E(key, A[0])

        # DEVIATION: The last Ai block is used to compute the S0 encryption block (rather that the first A0 block)
        if enc_tag_dev1 == True:
                S0 = E(key, A[-1])

        # DEVIATION: The second A1 block is used to compute the S0 encryption block (rather that the first A0 block)
        elif enc_tag_dev2 == True:
                A1 = Flags + nonce + struct.pack('>H', 1)
                S0 = E(key, A1)

        # B.4.1.3 g)
        U = xor_strings(S0[:M], T)

        
	# # # #  # 
	# OUTPUT #
	# # # #  #
        
        return Ciphertext + U
        


    
def aes_ctr(text, key, frame_counter, src_addr, keyseqcounter, **devs):


        ''' 
        Specific implementation of CTR for 802.15.4-2003. See IEEE 802.15.4-2003 standard. Security level 1 (Encryption only).
        '''

        '''
        Handling deviation from the standard :
        Deviation handled are : Sec_level, Flag, Counter
        See security config file.
        '''

        Sec_level = devs.get('Sec_level', None)
        Flag = devs.get('Flag', None)
        Counter = devs.get('Counter', None)

        
        #if seclevel != 1:
        #        return text


        # # # # # # # # # # #  # 
        # INPUT TRANSFORMATION #
        # # # # # # # # # # #  # 
        
        # Preparing the nonce
        frame_counter = struct.pack('>I', frame_counter) # Endianess modified
        src_addr = struct.pack('>Q', src_addr)
        keyseqcounter = struct.pack('B', keyseqcounter)
        nonce = src_addr + frame_counter + keyseqcounter

        # DEVIATION: Nonce is formatted as a 2006 nonce (with security level 4)
        if Sec_level != None:
            nonce = src_addr + frame_counter + struct.pack('B', 4)

        # Flag used as padding in counter input blocks
        flag = struct.pack('B', 0b10000010)

        # DEVIATION: Flag is not set according to the CTR transformation specified in the 802.15.4 specification
        if Flag != None:
                flag = struct.pack('B', Flag)

        m = text
        key = key.decode("hex")
        
        # Parsing the text as 16-bytes blocks
        # However, the last block can be less than 16-bytes in size
        Data = []

        while m != '':
                if len(m) < 16:
                        Data.append(m)
                        m = ''
                else:
                        Data.append(m[:16])
                        m = m[16:]
        

        # # # # # # # # # # # # # # # # # # # # # 
	# ENCRYPTION/ DECRYPTION TRANSFORMATION #
        # # # # # # # # # # # # # # # # # # # # #

        newtext = ""

        for c,P in enumerate(Data):
                counter = struct.pack('>H', c)

                # DEVIATION: First counter used to compute encrypted block is not 0 but 1
                if Counter == True:
                        counter = struct.pack('>H', c+1)

                Ti = flag + nonce + counter
                if c == len(Data) - 1:  # Last block
                        Ci = xor_strings(E(key, Ti)[:len(P)], P)
                else:        
                        Ci = xor_strings(E(key, Ti), P)
                newtext += Ci


        
	# # # #  # 
	# OUTPUT #
	# # # #  #
                
        return newtext

                
def aes_ccm_inverse(text, header, key, seclevel, frame_counter, src_addr, keyseqcounter, **devs):


        ''' 
        Specific implementation of inverse CCM for 802.15.4-2003. See IEEE 802.15.4-2003 standard.
        Security level from 2 to 4 (Encryption + Authentication).
        '''

        '''
        Handling deviation from the standard :
        Deviation handled are : sec_dev, auth_flag_dev, auth_tag_dev, enc_flag_dev, enc_block_dev, enc_tag_dev1, enc_tag_dev2
        See security config file.
        '''

        auth_flag_dev = devs.get('auth_flag_dev', None)
        auth_tag_dev = devs.get('auth_tag_dev', None)
        enc_flag_dev = devs.get('enc_flag_dev', None)
        enc_block_dev = devs.get('enc_block_dev', None)
        enc_tag_dev1 = devs.get('enc_tag_dev1', None)
        enc_tag_dev2 = devs.get('enc_tag_dev2', None)
        sec_dev = devs.get('sec_dev', None)

        
        if not seclevel in [2,3,4]:
                return text

        # M : Number of octets in authentication field
        # L : Number of octets in legth field

        L = 2  # As stated in specification IEEE Std 802.15.4-2003
        
        seclevel = hex(int(seclevel))
        M_id = {"0x2" : 16, "0x3" : 8, "0x4" : 4}
        M = M_id[seclevel]

        # # # # # # # # # # #  # 
        # INPUT TRANSFORMATION #
        # # # # # # # # # # #  # 

        # Preparing the nonce
        frame_counter = struct.pack('>I', frame_counter)
        src_addr = struct.pack('>Q', src_addr)
        keyseqcounter = struct.pack('B', keyseqcounter)
        nonce = src_addr + frame_counter + keyseqcounter

        # DEVIATION: Nonce deviation for 2003 trame using 2006 nonce
        if sec_dev == True:
                nonce = src_addr + frame_counter + struct.pack('B', int(seclevel,16))

        # Preparing the Additional authenticated data
        a = header
        lengthA = struct.pack('>H', len(a))
        AddAuthData = addZerosTobeDivisibleBy162(lengthA + a)

        # Parsing the message c as (m || U)
        c = text        
        m = c[:-M]  # encrypted text
        U = c[-M:] # encrypted MIC

        # Forming padded message CiphertextData
        CiphertextData = addZerosTobeDivisibleBy162(m)
        
        key = key.decode('hex')
        

        # # # # # # # # # # # # # # #
	# DECRYPTION TRANSFORMATION #
        # # # # # # # # # # # # # # #

        cleartext = ""

        # Formating flag2
	flag2 = struct.pack('B', L-1)

        # DEVIATION: Input flag 'flag2' is not set according to the CCM specification
        if enc_flag_dev != None:
                flag2 = struct.pack('B', enc_flag_dev)

        # Formating A0
	A0 = flag2 + nonce + struct.pack('H', 0)

        # Running AES-CTR
	for i in range(len(CiphertextData)/16):

		Mi = CiphertextData[(i*16):(i*16+16)]
                counter = struct.pack('>H', i+1)

                # DEVIATION : Block A0 is used as a first block for encryption
                if enc_block_dev != None:
                        counter = struct.pack('>H', i)

		Ai = flag2 + nonce + counter
		Ci = xor_strings(E(key, Ai), Mi)
		cleartext = cleartext + Ci

        # Dencrypting the MIC using A0
        S0 = E(key, A0)

        # DEVIATION : The last Ai block is used to compute the S0 encryption block (rather that the first A0 block)
        if enc_tag_dev1 == True and CiphertextData != '':
                S0 = E(key, Ai)

        # DEVIATION : The second A1 block is used to compute the S0 encryption block (rather that the first A0 block)
        elif enc_tag_dev2 == True:
                A1 = flag2 + nonce + struct.pack('>H', 1)
                S0 = E(key, A1)

        T = xor_strings(S0[:M], U)

        # Keeping the len(m) leftmost octets 
        cleartext = cleartext[:len(m)]

        
        # # # # # # # # # # # # # # # # # # # # #
        # AUTHENTICATION CHECKING TRANSFORMATION #
        # # # # # # # # # # # # # # # # # # # # #

        # Forming the padded message PlaintextData
        PlaintextData = addZerosTobeDivisibleBy162(cleartext)

        #Forming the message AuthData such as AuthData = AddAuthData || PlaintextDat
        AuthData = AddAuthData + PlaintextData

        B, X  = [], []
        
        # Formating flag1
        flag1 = struct.pack('B', (1 << 6) + ((M-2)/2 << 3) + (L-1))

        # DEVIATION : Input flag 'flag1' is not set according to the CCM specification
        if auth_flag_dev != None:
                flag1 = struct.pack('B', auth_flag_dev)

        
        # Formating B0
        lengthM = struct.pack('>H', len(m))
        B.append(flag1 + nonce + lengthM)  # B0 (16-octets block)

        # Formating B1 -> Bn (16-octets-)blocks with data to authenticate
        for i in range(len(AuthData)/16):
                B.append(AuthData[(i*16):(i*16+16)])

        # Formating null initial vector X0
        X.append(struct.pack('16x'))

        # Running AES-CBC
        for i in range(len(B)):
                XxorB = xor_strings(X[i], B[i])
                X.append(E(key, XxorB))

        # Getting clear MIC
        T_check = X[-1][:M]

        # DEVIATION : T is obtained by ommiting all but the rightmost M octets of the
        # last X computed block (rather than the leftmost M octets)
        if auth_tag_dev == True:
                T_check = X[-1][-M:]
        

        
	# # # #  # 
	# OUTPUT #
	# # # #  #
        
        return cleartext, (T_check == T)



        
def aes_ccm(text, header, key, seclevel, frame_counter, src_addr, keyseqcounter, **devs):

        '''
        Specific implementation of CCM for 802.15.4-2003. See IEEE 802.15.4-2003 standard.
        Security level from 2 to 4 (Encryption + Authentication).
        ''' 

        '''
        Handling deviation from the standard :
        Deviation handled are : sec_dev, auth_flag_dev, auth_tag_dev, enc_flag_dev, enc_block_dev, enc_tag_dev1, enc_tag_dev2
        See security config file.
        '''

        auth_flag_dev = devs.get('auth_flag_dev', None)
        auth_tag_dev = devs.get('auth_tag_dev', None)
        enc_flag_dev = devs.get('enc_flag_dev', None)
        enc_block_dev = devs.get('enc_block_dev', None)
        enc_tag_dev1 = devs.get('enc_tag_dev1', None)
        enc_tag_dev2 = devs.get('enc_tag_dev2', None)
        sec_dev = devs.get('sec_dev', None)

        
        if not seclevel in [2,3,4]:
                return text

        # M : Number of octets in authentication field
        # L : Number of octets in legth field

        L = 2  # As stated in specification IEEE Std 802.15.4-2003
        
        seclevel = hex(int(seclevel))
        M_id = {"0x2" : 16, "0x3" : 8, "0x4" : 4}
        M = M_id[seclevel]

        # Preparing the nonce
        frame_counter = struct.pack('>I', frame_counter)
        src_addr = struct.pack('>Q', src_addr)
        keyseqcounter = struct.pack('B', keyseqcounter)
        nonce = src_addr + frame_counter + keyseqcounter

        # DEVIATION : Nonce deviation for 2003 trame using 2006 nonce
        if sec_dev == True:
                nonce = src_addr + frame_counter + struct.pack('B', int(seclevel,16))

        
        # # # # # # # # # # #  # 
        # INPUT TRANSFORMATION #
        # # # # # # # # # # #  # 

        key = key.decode("hex")
        
        a = header
        lengthA = struct.pack('>H', len(a))
        AddAuthData = addZerosTobeDivisibleBy162(lengthA + a)
        
        m = text
        PlaintextData = addZerosTobeDivisibleBy162(m)

        AuthData = AddAuthData + PlaintextData

        
        # # # # # # # # # # # # # # # # #
        # AUTHENTICATION TRANSFORMATION #
        # # # # # # # # # # # # # # # # #
        
        B, X  = [], []
        
        # Formating flag1
        flag1 = struct.pack('B', (1 << 6) + ((M-2)/2 << 3) + (L-1))

        # DEVIATION : Input flag 'flag1' is not set according to the CCM specification
        if auth_flag_dev != None:
                flag1 = struct.pack('B', auth_flag_dev)

        # Formating B0
        lengthM = struct.pack('>H', len(m))
        B.append(flag1 + nonce + lengthM)  # B0 (16-octets block)

        # Formating B1 -> Bn (16-octets-)blocks with data to authenticate
        for i in range(len(AuthData)/16):
                B.append(AuthData[(i*16):(i*16+16)])

        # Formating null initial vector X0
        X.append(struct.pack('16x'))

        # Running AES-CBC
        for i in range(len(B)):
                XxorB = xor_strings(X[i], B[i])
                X.append(E(key, XxorB))

        # Getting clear MIC
        T = X[-1][:M]

        # DEVIATION : T is obtained by ommiting all but the rightmost M octets of the
        # last X computed block (rather than the leftmost M octets)
        if auth_tag_dev == True:
                T= X[-1][-M:]

                
        # # # # # # # # # # # # # # #
	# ENCRYPTION TRANSFORMATION #
        # # # # # # # # # # # # # # #

        Ciphertext = ""

        # Formating flag2
	flag2 = struct.pack('B', L-1)

        # DEVIATION : Input flag 'flag2' is not set according to the CCM specification
        if enc_flag_dev != None:
                flag2 = struct.pack('B', enc_flag_dev)

        # Formating A0
	A0 = flag2 + nonce + struct.pack('H', 0)

        # Running AES-CTR
	for i in range(len(PlaintextData)/16):
		Mi = PlaintextData[(i*16):(i*16+16)]
                counter = struct.pack('>H', i+1)

                # DEVIATION : Block A0 is used as a first block for encryption
                if enc_block_dev != None:
                        counter = struct.pack('>H', i)

		Ai = flag2 + nonce + counter
		Ci = xor_strings(E(key, Ai), Mi)
		Ciphertext = Ciphertext + Ci

        # Encrypting the MIC using A0
        S0 = E(key, A0)

        # DEVIATION : The last Ai block is used to compute the S0 encryption block (rather that the first A0 block)
        if enc_tag_dev1 == True and PlaintextData != '':
                S0 = E(key, Ai)

        # DEVIATION : The second A1 block is used to compute the S0 encryption block (rather that the first A0 block)
        elif enc_tag_dev2 == True:
                A1 = flag2 + nonce + struct.pack('>H', 1)
                S0 = E(key, A1)

        U = xor_strings(S0[:M], T)

        # Keeping the len(m) leftmost octets 
        Ciphertext = Ciphertext[:len(m)]

        
	# # # #  # 
	# OUTPUT #
	# # # #  #

	c = Ciphertext + U

	return c



        
        
