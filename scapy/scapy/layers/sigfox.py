from scapy.packet import *
from scapy.fields import *
import struct
 
class Sigfox(Packet):

  name = "Sigfox"
  fields_desc = [
    BitField("reserved", 0, 2),
    BitEnumField("ack", 0, 1, {0:"Disabled", 1:"Enabled"}),
    BitField("reserved1", 0, 1),
    BitField("cpt", 0,12),
    XLEIntField("adresse", 0x0),
  ]

  def post_build(self, p, pay):
    val_sync_word ={1: 0xA08D0,2: 0xA35F8,3: 0xA35F4,4: 0xA35F0,5: 0xA611C,6: 0xA6118,7: 0xA6114,8: 0xA6110,9: 0xA94CC,10: 0xA94C8,11: 0xA94C4,12: 0xA94C0} 
    len_pay = len(pay) #pay = raw
    assert(len_pay > 0 and len_pay <= 12)
    assert(self.cpt >= 0 and self.cpt < 4096)
    p_synccpt = (val_sync_word[len_pay]|(self.ack<<1)) << 12 | self.cpt #4 octets
    synccpt = struct.pack(">I", p_synccpt)
    adr = struct.pack(">I", self.adresse)
    #crc = "\xBE\xEFtot"  #TODO : Appeler une fonction qui calcule le crc avec en parametre p et pay, a partir de pay on enleve le crc, on le dechiffre et on affiche si ok ou pas
    return synccpt + adr + pay #+ crc      


  def pre_dissect(self, s): 
    return s[2:] #s[2:len(s)-5] without the CRC


