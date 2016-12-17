from scapy.all import *
from transmissions import Transmission

class Recipient(object):

    def __init__(self, originator, recipient,  pkt, **kwargs):
        self.device = recipient
        self.originator = originator
        self.transmissions = [Transmission(self.originator, pkt, **kwargs)]        

    def merge(self, recipient):

        assert(self.has_same_destination_device(recipient.device))
        
        for _transmission in recipient.transmissions:

            transmission = self.search_transmission(_transmission.get_parameters())

            if transmission:
                # Found a transmission which shares the same parameters
                transmission.merge(_transmission)
            else:
                # New transmission parameters found
                self.transmissions.append(_transmission)
                self.transmissions[-1].originator = self.originator


    def get_dict(self):

        js = {}

        js['id'] = self.device.id

        t_list = []
        for t in self.transmissions:
            t_list.append(t.get_dict())

        js['Transmissions'] = t_list
            
        return js


    def look_for_sixlowpan(self):

        for transmission in self.transmissions:
            if transmission.frametype == 1: # Data
                transmission.look_for_sixlowpan()
                
        

    def feed(self, pkt, **parameters):

        transmission = self.search_transmission(parameters)

        if transmission:
            # Found a transmission which shares the same parameters
            transmission.feed(pkt)

            if 'security' in parameters:
                transmission.security = parameters['security']

        else:
            # New transmission parameters found
            _transmission = Transmission(self.originator, pkt, **parameters)

            if 'security' in parameters:
                _transmission.security = parameters['security']

            self.transmissions.append(_transmission)

    # Look for each transmission, if security has been used.
    def security_exist(self):
        for trans in self.transmissions:
            if trans.security_exist():
                return True
        return False


    def unknown_security_policy(self):
        
        for transmission in self.transmissions:
            if transmission.unknown_security_policy():
                return True
        return False

    
    def guess_deviations(self):
        
        for transmission in self.transmissions:
            transmission.guess_deviation()


    def handle_encryption_keys(self, key=""):
        
        if key != "":
            for transmission in self.transmissions:
                if transmission.security_exist():
                    transmission.handle_encryption_key(key)

        else:
            cnt = 0
            for transmission in self.transmissions:
                if transmission.security_exist():
                    cnt+=1
                if cnt == 2:
                    break

            key = ""                    

            if cnt == 2:
                print "Several transmission types has been secured between Device %d and Device %d" % (self.originator.id, self.device.id)

                print "\n******************************************************\n"
                self.originator.show_light(opt="\t")
                print "\n******************************************************\n"
                self.device.show_light("\t")
                print "\n******************************************************\n"

                while(1):
                    resp = raw_input("Is the encryption key the same for each transmission? (y/n) : ")
                    if resp in ["y","n","Y","N"]:
                        break
                if resp in ["y", "Y"]:
                    while(1):
                        key = raw_input("Provide the 16 bytes encryption key used by Device %d to communicate with Device  %d (format = 0xAAAAAAAAAAAAAAAA) : " % (self.originator.id, self.device.id))
                        if key and key[:2] == "0x" and len(key[2:]) == 32:
                            try:
                                int(key,16)
                                break
                            except Exception:
                                pass

            else: 
                print "A single transmission type has been secured between Device %d and Device %d" % (self.originator.id, self.device.id)

                print "\n******************************************************\n"
                self.originator.show_light("\t")
                print "\n******************************************************\n"
                self.device.show_light("\t")
                print "\n******************************************************\n"


            for transmission in self.transmissions:
                if transmission.security_exist():
                        transmission.handle_encryption_key(key)

                    

    def guess_security(self):

        for transmission in self.transmissions:
            transmission.guess_security()

                
    def search_transmission(self, parameters):

        for transmission in self.transmissions:
            if transmission.has_same_parameters(parameters):
                return transmission

    def has_same_destination_device(self, device):
        return (self.device == device)

    def show(self, opt=''):

        print "%sDestination device %d" % (opt,self.device.id)
        for transmission in self.transmissions:
            transmission.show(opt=opt+'\t')

