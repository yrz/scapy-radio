#!/usr/bin/python2

# Copyright (C) Airbus Defence and Space
# Authors: Enzo Laurent, Adam Reziouk, Jonathan-Christofer Demay

## This program is free software; you can redistribute it and/or modify it 
## under the terms of the GNU General Public License version 3 as
## published by the Free Software Foundation.
##
## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details

from scapy.all import *
import time


def get_channel(timeout):

        
    
	load_module('gnuradio')
	switch_radio_protocol("Zigbee")
	print "Launching Gnuradio in background..."
	time.sleep(6)

	chan = 11

	while chan <= 26:
		gnuradio_set_vars(Channel=chan)
		time.sleep(0.3)
		print "Searching on channel " + str(chan) + "..."
                pckt = sniffradio(timeout=timeout)
                if len(pckt) != 0 :
                    print "\n    Packets detected on channel " + str(chan)
                    print

		chan = chan + 1
