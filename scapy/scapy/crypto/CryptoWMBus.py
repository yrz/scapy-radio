#!/usr/bin/python

from Crypto.Cipher import AES,DES

def AES_Enc_FCT(key, message):
	cipher = AES.new(key)
	return cipher.encrypt(message)

def AES_Dec_FCT(key, message):
	cipher = AES.new(key)
	return cipher.decrypt(message)

def DES_Enc_FCT(key, message):
	cipher = DES.new(key)
	return cipher.encrypt(message)

def DES_Dec_FCT(key, message):
	cipher = DES.new(key)
	return cipher.decrypt(message)

def xor_strings(xs, ys):
	return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

def addPadding(string,modulus):
	string = '\x2F\x2F' + string
	if (len(string)%modulus) != 0:
		for i in range(modulus - (len(string)%modulus)):
			string = string + "\x2F"
	return string



############################ AES-CTR ####################################

def AES_CTR_ENCRYPT(input, key, ctr):
	"""
	AES Counter encryption function for WMBus Protocol

	Counter fields from WMBus layer
	field	    | M A CC SN FN BC
	size (o)	| 2 6  1  4  2  1

	No padding in CTR mode
	"""

	if len(ctr) != 16:
		raise Exception("Bad CTR Len")
	if len(key) != 16:
		raise Exception("Bad key Len")

	#Count blocks
	nb_blocs=len(input) / 16
	if len(input) % 16:
		nb_blocs += 1

	out=""
	for i in xrange(nb_blocs):
		clear=input[:16]
		ciph=AES_Enc_FCT(key,ctr)
		out += xor_strings(clear,ciph[:len(clear)]) 
		
		input=input[16:]

		#increment ctr
		inc = chr(ord(ctr[-1])+1)
		ctr = ctr[:-1] + inc

	print "ON EST ALLLL"
	return out

def AES_CTR_DECRYPT(input, key, ctr):
	"""
	AES Counter decryption function for WMBus Protocol
	Symetric algorithm
	"""
	return AES_CTR_ENCRYPT(input, key, ctr)




############################ AES-CBC ####################################

def AES_CBC_ENCRYPT(input, key, iv):
	"""
	AES Cipher Block Chaining encryption function for WMBus Protocol

	IV fields from WMBus layer
	field	    | M A ACC
	size (o)	| 2 6  8
	"""

	if len(iv) != 16:
		raise Exception("Bad IV Len")
	if len(key) != 16:
		raise Exception("Bad key Len")

	clear=addPadding(input,16) #Pad with \x2F before & after

	#Count blocks
	nb_blocs=len(clear) / 16

	#Encrypt
	out=""
	ciph=iv
	for i in xrange(nb_blocs):
		xored=xor_strings(clear[:16],ciph)
		ciph=AES_Enc_FCT(key,xored)
		clear=clear[16:]
		out += ciph

	return out

def AES_CBC_DECRYPT(input, key, iv):
	"""
	AES Cipher Block Chaining decryption function for WMBus Protocol

	IV fields from WMBus layer
	field	    | M A ACC
	size (o)	| 2 6  8
	"""

	if len(iv) != 16:
		raise Exception("Bad IV Len")
	if len(key) != 16:
		raise Exception("Bad key Len")


	#Count blocks
	nb_blocs=len(input) / 16

	#Decrypt
	out=""
	prev_ciph=iv
	for i in xrange(nb_blocs):
		xored=AES_Dec_FCT(key,input[:16])
		out += xor_strings(xored,prev_ciph)
		prev_ciph=input[:16]
		input=input[16:]

	#Check decryption
	if out[0:2] == '\x2F\x2F':
		print "Decrypt OK"

	#Remove padding
	cpt=0
	for i in out[::-1]:
		if i == "\x2F":
			cpt+=1
		else:
			break
	out=out[:-cpt]
	return out




############################ DES-CBC ####################################


def DES_CBC_ENCRYPT(input, key, iv):
	"""
	DES Cipher Block Chaining encryption function for WMBus Protocol

	IV fields from WMBus layer
	field	    | ID MAN DATE (type G Record - EN13757-3)
	size (o)	|  4  2   2
	"""

	key=key[:8]

	if len(iv) != 8:
		raise Exception("Bad IV Len")
	if len(key) != 8:
		raise Exception("Bad key Len")

	clear=addPadding(input,8) #Pad with \x2F before & after

	#Count blocks
	nb_blocs=len(clear) / 8

	#Encrypt
	out=""
	ciph=iv
	for i in xrange(nb_blocs):
		xored=xor_strings(clear[:8],ciph)
		ciph=DES_Enc_FCT(key,xored)
		clear=clear[8:]
		out += ciph

	return out

def DES_CBC_DECRYPT(input, key, iv):
	"""
	DES Cipher Block Chaining decryption function for WMBus Protocol

	IV fields from WMBus layer
	field	    | ID MAN DATE (type G Record - EN13757-3)
	size (o)	|  4  2   2
	"""

	key=key[:8]

	if len(iv) != 8:
		raise Exception("Bad IV Len")
	if len(key) != 8:
		raise Exception("Bad key Len")


	#Count blocks
	nb_blocs=len(input) / 8

	#Decrypt
	out=""
	prev_ciph=iv
	for i in xrange(nb_blocs):
		xored=DES_Dec_FCT(key,input[:8])
		out += xor_strings(xored,prev_ciph)
		prev_ciph=input[:8]
		input=input[8:]


	#Check decryption
	if out[0:2] == '\x2F\x2F':
		print "Decrypt OK"

	#Remove padding
	cpt=0
	for i in out[::-1]:
		if i == "\x2F":
			cpt+=1
		else:
			break
	out=out[:-cpt]
	return out

