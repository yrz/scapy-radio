#!/usr/bin/python2

'''
This program uses the 802.15.4 network database which has been added as a scapy-radio contribution
'''

from scapy.all import *
from getChannel import *
from dot15d4_database import *
import time

TIMEOUT = 10

class mainFSM(Automaton):

    def parse_args(self, **kwargs):
        Automaton.parse_args(self, **kwargs)

    def master_filer(self, pkt):
        return (Dot15d4FCS in pkt)
    
    @ATMT.state(initial=1)
    def begin(self):
        self.t0 = time.time()
        self.nwdb = NetworkDataBase("802.15.4 Network Database")
        raise self.waiting()

    @ATMT.state()
    def waiting(self):
        pass


    @ATMT.receive_condition(waiting)
    def receive_packet(self, pkt):

        if time.time() - self.t0 > TIMEOUT:
            raise self.prepare_output()
            
        self.nwdb.handlepacket(pkt)
        raise self.waiting()


    @ATMT.timeout(waiting, 1)
    def timeout_elsapsed(self):

        if time.time() - self.t0 > TIMEOUT:
            raise self.prepare_output()


    @ATMT.state()
    def prepare_output(self):

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
        raise self.handle_higher_protocol()


    @ATMT.state()
    def handle_higher_protocol(self):

        if self.nwdb.devices == []:
            raise self.end()
        
        while 1 :

            resp = raw_input('Do you want to look for higer layer protocol ? (0) No, (1) SixLoWPAN : ')

            if resp not in ['0', '1']:
                print 'Bad response'

            elif resp == '0':
                break

            else:
                self.nwdb.look_for_sixlowpan()
                break

        raise self.end()
    

    @ATMT.state(final=1)
    def end(self):
        self.nwdb.show()
        self.nwdb.generate_json()
        return



higher_protocol = ['sixlopan']


def start_scan(channel=18):

    load_module('gnuradio')
    
    conf.L2listen=GnuradioSocket_in
    conf.L3socket=GnuradioSocket_out

    switch_radio_protocol("dot15d4")

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

                    try:
                        
                        if int(answer) <= 26 and int(answer) >= 11 :                    
                            channel = int(answer)
                            break

                    except:
                        pass

                while(1):

                    answer = raw_input("Precise the timeout for scan (format : int or float) : ")
                    
                    try:
                        timeout = int(answer)
                        break

                    except ValueError:
                        
                        try:
                            timeout = float(answer)
                            break

                        except ValueError:
                            pass


                TIMEOUT = timeout

                start_scan(channel=channel)
                        
            break

