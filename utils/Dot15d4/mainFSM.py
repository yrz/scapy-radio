#!/usr/bin/python2

# Copyright (C) Airbus Defence and Space
# Authors: Adam Reziouk, Enzo Laurent, Jonathan-Christofer Demay

## This program is free software; you can redistribute it and/or modify it 
## under the terms of the GNU General Public License version 3 as
## published by the Free Software Foundation.
##
## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details

'''
This program uses the 802.15.4 network database which has been added as a scapy-radio contribution
'''

from scapy.all import *
from getChannel import *

try:
    load_contrib('scanner_802_15_4')
except:
    print 'Impossible to load scanner_802_15_4'
    exit()

class mainFSM(Automaton):

    def parse_args(self, **kwargs):
        Automaton.parse_args(self, **kwargs)

    def master_filer(self, pkt):
        return (Dot15d4FCS in pkt)

    @ATMT.state(initial=1)
    def begin(self):
        self.nwdb = NetworkDataBase("WIN4SMART")
        # Initialize things
        raise self.waiting()

    @ATMT.state()
    def waiting(self):
        pass

    @ATMT.receive_condition(waiting)
    def receive_packet(self, pkt):
        self.nwdb.handlepacket(pkt)
        raise self.waiting()

    @ATMT.timeout(waiting, 12)
    def timeout_elsapsed(self):

        print "\n\nEnd of scan\n\n" 
        self.nwdb.set_ids() # Assign an id for each device
        raise self.handle_security()

    @ATMT.state()
    def handle_security(self):
        if self.nwdb.security_exist():
            while(1):
                resp = raw_input("Security has been used during communication, do you want to guess the security policy? (y/n) : ")
                if resp in ["y","n","Y","N"]:
                    break
            if resp in ["y", "Y"]:
                self.nwdb.guess_security()
        raise self.end()
            
    @ATMT.state(final=1)
    def end(self):
        self.nwdb.show()

        print self.nwdb.generate_xml()

        return

    
def start_scan(channel=18):

    load_module('gnuradio')
    conf.L2listen=GnuradioSocket_in
    conf.L3socket=GnuradioSocket_out

    switch_radio_protocol("Zigbee")
    print "Launching Gnuradio in background..."
    time.sleep(6)
    gnuradio_set_vars(Channel=channel)

    scan = mainFSM()
    scan.run()
    
if __name__ == '__main__':
    
    bann = "\n\n\t\t************************************\n\t\t* WELCOME TO 802.15.4 Scanner Tool *\n\t\t************************************\n"

    print bann

    print "\t\t ENSURE THAT A SDR IS PLUGGED IN \n"
    
    while(1):
        answer = raw_input("What do you want to do? ------> (1) Find the active channel / (2) Start the scan : ")    
        if answer in ['1','2']:

            if answer == '1':
                while(1):
                    answer = raw_input("Precise the timeout per channel (format : int or float) : ")
                    
                    try:
                        timeout = int(answer)
                        get_channel(timeout)
                        break

                    except ValueError:
                        
                        try:
                            timeout = float(answer)                            
                            get_channel(timeout)
                            break

                        except ValueError:
                            pass

            else:
                while(1):
                    answer = raw_input("Which channel to use (11 <= channel <= 26) : ")
                    
                    if int(answer) <= 26 and int(answer) >= 11 :                    
                        start_scan(channel=int(answer))
                        break
            break
    
    print "End of scan"
