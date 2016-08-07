from recipient import Recipient
from lxml import etree

class Device(object):

    # TODO : set an id per device

    valid_attr = {
        'addr16' : lambda x: (x <= 0xffff) and (x > 0), # TODO : take care about 0xfffe
        'addr64' : lambda x: (x < 0xffffffffffffffff) and (x > 0),
        'panid' : lambda x: (x < 0xffff) and (x > 0),
        'coord' : lambda x: x == 1,
        'pancoord' : lambda x: x == 1,
        'beacon_enabled' : lambda x: x == 1
    }

    def is_instance_a_device(self, arg):
        assert(isinstance(arg,Device)), "arg is not a Device instance"

    def __init__(self, **kwargs):
        self.update(**kwargs)
        self.recipients = []
        
    def update(self, **kwargs):
        self.__dict__.update((k, v) for k, v in kwargs.iteritems() if (k in self.valid_attr) and self.valid_attr[k](v))
        for k,v in kwargs.iteritems():
                print "%s" % (k) + str(v)

    def __getattr__(self, attr):
        return self.__dict__.get(attr,None)


    def parse_xml(self, xdevice):
        
        self.id = int(xdevice.attrib['id'])

        for elem in xdevice:

            if elem.tag != 'Recipient':
                    
                if elem.tag in Device.valid_attr:
                
                    self.__dict__[elem.tag] = int(elem.text, 16)
                
    
    def merge(self, device):

        self.is_instance_a_device(device)
        self.update(**device.__dict__)

        for _recipient in device.recipients:
            recipient = self.search_recipient(_recipient.device)
            if recipient:
                recipient.merge(_recipient)
                device.recipients.remove(_recipient)
            else:
                _recipient.originator = self
        
        self.recipients.extend(device.recipients)
                
    # Look for each recipient, if security has been used during communication.
    def security_exist(self):
        
        for recipient in self.recipients:
            if recipient.security_exist():
                return True
        return False

    def handle_encryption_keys(self, key=""):

        for recipient in self.recipients:
            if recipient.security_exist():
                if key != "": # single key
                    recipient.handle_encryption_keys(key)
                else:
                    recipient.handle_encryption_keys()

    def set_id(self, id):
        self.__dict__['id'] = id

    def unknown_security_policy(self):
        
        for recipient in self.recipients:
            if recipient.unknown_security_policy():
                return True
        return False

    def generate_xml(self):
        
        # ADD ID

        device = etree.Element("Device")
        device.set('id', str(self.id))

        for k,v in self.__dict__.iteritems():
            if k in self.valid_attr:
                element = etree.Element(k)
                element.text = hex(v)
                device.append(element)

        for recipient in self.recipients:
            element = recipient.generate_xml()
            device.append(element)

        return device


    def guess_deviations(self):
        
        for recipient in self.recipients:
            recipient.guess_deviations()

    
    def guess_security(self):

        for recipient in self.recipients:
            recipient.guess_security()

        
    def register_transmission(self, device, pkt, **kwargs):

        self.is_instance_a_device(device)
        
        recipient = self.search_recipient(device)

        if recipient:
            recipient.feed(pkt, **kwargs)
        else:
            _recipient = Recipient(self, device, pkt, **kwargs)
            self.recipients.append(_recipient)
            

    def search_recipient(self, device):

        for recipient in self.recipients:

            if recipient.has_same_destination_device(device):
                return recipient
        

    def show_light(self, opt=''):
        
        print "%sDevice %d" % (opt, self.id)

        for k, v in self.__dict__.iteritems():
            if (k in self.valid_attr):
                print " %s %s : 0x%x" % (opt,k,v)
        
        

    def show(self, opt=''):

        print "%sDevice %d" % (opt, self.id)


        for k, v in self.__dict__.iteritems():
            if (k in self.valid_attr):
                print " %s %s : 0x%x" % (opt,k,v)             

        if not self.recipients:
            print "%s [No recipient found for this device]" % opt
        else:
            for recipient in self.recipients:
                recipient.show(opt=opt+'\t')
            
            
if __name__ == '__main__':
    
    a = Device(addr16=1L, panid=2L)
    b = Device(addr64=3L, panid=4L)
    b.merge(a)

    a.search_recipient(b)
    
    print "test get attr %d" % a.panid
    
    a.show()
    b.show()
