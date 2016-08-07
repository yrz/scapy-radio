from security import *
from lxml import etree

class Transmission(object):

    valid_attr = {
        "data" : lambda x: x==1,
        "cmd" : lambda x: x==1,
        "cmd_id" : lambda x: x>=0 and x<=9,
        'security_enabled' : lambda x: x==0 or x==1,
        'security_level' : lambda x: x >=1 and x < 8,
        'frame_version' : lambda x: x == 0 or  x == 1,
        'indirect_transmission' :  lambda x: x == 0 or x == 1,
        'srcaddrmode' : lambda x: ((x == 0) or  (x == 2) or (x == 3)),
        'destaddrmode' : lambda x: ((x == 0) or  (x == 2) or (x == 3)),
        'key' : lambda x: type(x) == str
    }
    
    def __init__(self, owner, pkt, **kwargs):

        if 'key' in kwargs:
            if kwargs['key'][-1] == 'L':
                kwargs['key'] = kwargs['key'][:-1]
                
        self.__dict__.update((k, v) for k, v in kwargs.iteritems() if (k in self.valid_attr) and self.valid_attr[k](v))
        self.counter = 1
        self.originator = owner
        self.packets_buffer = [pkt]

        if 'security' in kwargs:
            self.__dict__.update({'security' : kwargs['security']})
        
        elif self.security_exist():
            self.__dict__.update({'security' : SecurityFeatures()})


    def __getattr__(self, attr):
        return self.__dict__.get(attr,None)

    def generate_xml(self):
        
        transmission = etree.Element("Transmission")
        
        for k, v in self.__dict__.iteritems():
            if k in self.valid_attr:
                element = etree.Element(k)
                if k == 'key':
                    element.text = v
                else:
                    element.text = hex(v)
                    if element.text[-1] == 'L':
                        element.text = element.text[:-1]
                transmission.append(element)

        if self.security_enabled:
            element = self.security.generate_xml()
            transmission.append(element)
        
        return transmission
                
        
    def feed(self, pkt):
        self.counter += 1
        try:
            self.packets_buffer.append(pkt)
        except:
            print "Packet buffer is full"
            self.counter = len(self.packets_buffer)

        
    def merge(self, transmission):
        
        self.counter += transmission.counter
        
        try:
            self.packets_buffer.extend(transmission.packets_buffer)
        except:
            print "Packet buffer is full"
            self.counter = len(self.packets_buffer)

    def security_exist(self):
        return self.security_enabled


    def unknown_security_policy(self):
        
        if not self.security_exist():
            return False
            
        if self.security.security_found:
            return False

        return True


    def guess_deviation(self):
        
        if self.unknown_security_policy():
            self.security.guess_deviation(self, self.packets_buffer, self.key, self.frame_version)

    def guess_security(self):
        
        if not self.security_exist():
            return
        
        if not self.__dict__.has_key('key'):
            print "Encryption key missing"
            return
            
        
        #self.security.guess_security(self, self.packets_buffer[0], self.key, self.frame_version)
        self.security.guess_security(self, self.packets_buffer, self.key, self.frame_version)
        
    def handle_encryption_key(self, key=''):
        
        # check if security has been enabled
        if not self.security_exist():
            return

        if key == '':
            print "Security has been used for the following transmission : \n"

            while(1):
                
                self.show_light(opt='\t')
                print "\n******************************************************\n"

                key = raw_input("Provide the 16 bytes encryption key used for the transmission printed above (format = 0xAAAAAAAAAAAAAAAA) : ")
                if key and key[:2] == "0x" and len(key[2:]) == 32:
                    try:
                        int(key,16)
                        break
                    except Exception:
                        pass


        self.__dict__['key'] = key
            
            

    def get_parameters(self):
        parameters = {}
        parameters.update((k,v) for k, v in self.__dict__.iteritems() if (k in self.valid_attr))
        return parameters
            
    def has_same_parameters(self, parameters):

        filtred_parameters = {}
        filtred_parameters.update((k,v) for k,v in parameters.iteritems() if (k in self.valid_attr) and self.valid_attr[k](v))

        return (not cmp(self.get_parameters(), filtred_parameters))


    def show_light(self, opt=''):

        print "%sParameters" % opt

        for k,v in self.get_parameters().iteritems():
            if (k in self.valid_attr):            
                print "%s %s = 0x%x" % (opt,k,v)
        

    def show(self, opt=''):
        print "%sParameters" % opt
        for k,v in self.get_parameters().iteritems():
            if k != 'key':
                print "%s %s = 0x%x" % (opt,k,v)
            else:
                print "%s %s = %s" % (opt, k, v)
        
        if self.security != None:
            self.security.show(opt=opt)

        print " %sCounter = %d" % (opt, self.counter)

        print " %sPackets stored are" % opt
        for p in self.packets_buffer:
            if len(p) > 50:
                print "%s %s ... %s  " % (opt , str(p)[:25].encode('hex') , str(p)[-25:].encode('hex'))
            else:
                print "%s  " % opt + str(p).encode('hex')
