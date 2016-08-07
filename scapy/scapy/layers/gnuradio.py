## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more information
## Copyright (C) Airbus Defence and Space
## Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan-Christofer Demay
## This program is published under a GPLv2 license

"""
Gnuradio layers, sockets and send/receive functions.
"""

from scapy.layers.ZWave import *
from scapy.layers.dot15d4 import *
from scapy.layers.bluetooth4LE import *
from scapy.layers.wmbus import *
from scapy.layers.zigbee import *
from scapy.layers.sixlowpan import *

_PROTOCOLS = {
    0: "Unknown",
    1: "ZWave",
    2: "802.15.4",
    3: "Bluetooth LE",
    4: "W-MBus",
    5: "Dash7",
    6: "Sigfox"
}


class GnuradioPacket(Packet):
    name = "Gnuradio header"
    fields_desc = [
    	ByteEnumField("proto", 0, _PROTOCOLS),
        ByteField("rfu1",0),
        ByteField("channel", 0),
        ByteField("rfu2", 0),
        ByteField("version", 0),
        ByteField("preamble", 0),
        ByteField("rf_psnr", 0),
        ByteField("extended", 0)
    ]


## Z-Wave
bind_bottom_up(GnuradioPacket, ZWave, proto=1)
bind_top_down(GnuradioPacket, ZWaveReq, proto=1)
bind_top_down(GnuradioPacket, ZWaveAck, proto=1)

## ZigBee
bind_layers(GnuradioPacket, Dot15d4FCS, proto=2)

## Bluetooth 4 LE
bind_layers(GnuradioPacket, BTLE, proto=3)

## WMBus
bind_layers(GnuradioPacket, WMBusLinkA, {"proto": 4, "version": 0})
bind_layers(GnuradioPacket, WMBusLinkB, {"proto": 4, "version": 1})

## Dash7
#bind_layers(GnuradioPacket, Dash7, proto=5)

conf.l2types.register(148, GnuradioPacket)
