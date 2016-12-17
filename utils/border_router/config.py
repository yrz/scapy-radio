SHORT_ADDR_MODE = 2
LONG_ADDR_MODE = 3

# When both short and extended link layer addresses are available, which one to use? 
DEFAULT_SRC_ADDR_MODE = SHORT_ADDR_MODE 
DEFAULT_DEST_ADDR_MODE = LONG_ADDR_MODE

DEFAULT_FRAME_VER = 1  # 0 -> 2003 / 1 -> 2006

# Security default conf
DEFAULT_SECURITY_ENABLED = 0
DEFAULT_SECURITY_POLICY = 7
DEFAULT_FRAME_COUNTER = 0x1
DEFAULT_KEYSEQCOUNTER = 0
DEFAULT_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # 16 octets

# In case extrended adress of frame to be secured cannot be found! 
USE_DEFAULT_EXTENDED_SRC_ADDR = 0
DEFAULT_EXTENDED_SRC_ADDR = 0x1122334455667788

# This is a hand-made NDP table. Keys of NDP_table correponds to IPv6 addresses.
# Value is a dictionnary of either a source or a long 802.15.4 address or both of them.
# Example : 
#
# user_ndp_table = {
#     "fe80::1" : { "long" : "0x44444444444444444", "short" : "0x5454"},
#     "fe80::5" : {"short" : "0x4777"}
#     }
user_ndp_table = {
    "fe80::1" : { "panid" : 5188, "short" : 0x1111, 'long':0x123456789},
    "fe80::2" : {"panid": 5188 , "short": 0x5000},
}
