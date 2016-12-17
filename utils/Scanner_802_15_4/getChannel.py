from scapy.all import *
import time


def get_channel(timeout):

        
    
	load_module('gnuradio')
	switch_radio_protocol("dot15d4")
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
