import sys
from device import Device
from transmissions import Transmission
from security import SecurityFeatures

class NetworkDataBase(object):

    def __init__(self, name, json=None):

        self.name = name
        self.devices = []
        self.associations_buffer = {}
        
    def generate_json(self):

        js = {}

        d_list = []
        for d in self.devices:
            d_list.append(d.get_dict())

        js['Devices'] = d_list

        js = json.dumps(js, indent=4, separators=(',',':'))
        
        #with open("/tmp/json_dot15d4.json", 'w') as json_nwdb:
        with open("./json_dot15d4.json", 'w') as json_nwdb:
            json_nwdb.write(js)
        
        return js


    def get_device_by_id(self, id):
        
        for device in self.devices:
            
            if device.id == id:
                
                return device

        return None


    def look_for_sixlowpan(self):

        for device in self.devices:
            device.look_for_sixlowpan()


    def is_device_known(self, device):
        self.is_instance_a_device(device)
        assert(device in self.devices),"Device instance does not exist in %s %s" % (self.name, self.__class__.__name__)

    def is_instance_a_device(self, arg):
        assert(isinstance(arg,Device)), "arg is not a Device instance"
        
    def register_device(self, device):
        self.is_instance_a_device(device)
        self.devices.append(device)

    def update_device(self, device, **kwargs):

        # Check if device exists in self.devices first
        self.is_device_known(device)        

        device.update(**kwargs)  ##DOWN##

    def search_device(self, panid, addr=None):

        #assert(addr64 <= 0xfffffffffffffffff or addr64 == None), "addr64 wrong format"
        #assert(addr16 <= 0xffff or addr16 == None), "addr16 wrong format"        
        assert(panid <= 0xffff), "panid wrong format"
        
        if addr:
            for device in self.devices:
                if (device.addr64 == addr or device.addr16 == addr) and (device.panid == panid):
                    return device
        else:
            # Look for pan coordinator with PAN Identifier = panid
            for device in self.devices:
                if device.panid == panid and device.pancoord:
                    return device

    def merge_devices(self, device1, device2):

        self.is_device_known(device1)
        self.is_device_known(device2)

        device1.merge(device2)
        
        for device in self.devices:
            for recipient in device.recipients:
                if recipient.device == device2:
                    recipient.device = device1

        self.devices.remove(device2)

        
    def register_transmission(self, device1, device2, pkt, **kwargs):
        
        self.is_device_known(device1)
        self.is_device_known(device2)        

        device1.register_transmission(device2, pkt, **kwargs)


    def set_ids(self):

        for idx, device in enumerate(self.devices):
            device.set_id(idx)

        
    def show(self):

        if not self.devices:
            print "%s %s is empty" % (self.name, self.__class__.__name__)

        else:

            print "%s Network Data Base result is :" % self.name
            for device in self.devices:
                print
                device.show(opt='\t')


    # Look for each device, if security has been used during communication.
    def security_exist(self):
        
        for device in self.devices:
            if device.security_exist():
                return True
        return False
            

    def handle_encryption_keys(self):
        
        while(1):
            resp = raw_input("Is the key encryption the same for all secured transmissions? (y/n) : ")
            if resp in ["y","n","Y","N"]:
                break

        key = ""
        if resp in ["y", "Y"]:
            while(1):
                key = raw_input("Provide the single encryption key (format = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA) : ")
                if key and key[:2] == "0x" and len(key[2:]) == 32:
                    try:
                        int(key,16)
                        break
                    except Exception:
                         pass
        
        for device in self.devices:
                device.handle_encryption_keys(key)



    def handle_deviations(self):
        
        while(1):
            resp = raw_input("The security of one or several secured transmission could not have been retrieved. Do you want to look for deviations? (y/n) : ")
            if resp in ["y","n","Y","N"]:
                break

        if resp in ['y', 'Y']:
            print 'Trying to find deviations related to security policies. This task can take time ...'
            for device in self.devices:
                device.guess_deviations()

    def guess_security(self):

        # Ask user to provide encryption key(s)
        self.handle_encryption_keys()

        for device in self.devices:
            device.guess_security()

        for device in self.devices:
            if device.unknown_security_policy():
                self.handle_deviations()
                break

        return

    def handlepacket(self, pkt):


        if pkt.proto == 0:  #invalid packet (invalid FCS)
            print "Invalid packet received / Dropped"            
            return
            

        if pkt.fcf_frametype == 0: # BEACON FRAME
            
            print "Beacon received"        
            
            if pkt.fcf_security:

                print 'Beacon is encrypted: Dropped (A bug must be fixed)'
                
                return

            device = self.search_device(pkt.src_panid, pkt.src_addr)

            if not device:

                device = Device(addr16 = (pkt.fcf_srcaddrmode == 2) and pkt.src_addr or None,
                                addr64 = (pkt.fcf_srcaddrmode == 3) and pkt.src_addr or None, 
                                panid = pkt.src_panid, coord = 1,
                                pancoord = pkt.sf_pancoord,
                                beacon_enabled = 1 if (pkt.sf_beaconorder < 15) else 0,
                                gts = pkt.gts_fields.gts_spec_permit)

                self.register_device(device)
        

        elif pkt.fcf_frametype == 1:
            
            print "Data received"

            # First search and create device
            
            src_panid = pkt.fcf_panidcompress and pkt.dest_panid or pkt.src_panid
            src_device = self.search_device(src_panid, pkt.src_addr)
            
            if not src_device:

                if pkt.fcf_srcaddrmode == 0:
                    # Source address not present
                    src_device = Device(coord=1, pancoord=1, panid=src_panid)
                else:
                    # Source address present
                    src_device = Device(addr16 = (pkt.fcf_srcaddrmode == 2) and pkt.src_addr or None,
                                        addr64 = (pkt.fcf_srcaddrmode == 3) and pkt.src_addr or None, 
                                        panid = src_panid)

                self.register_device(src_device)
                
            dest_device = self.search_device(pkt.dest_panid, pkt.dest_addr)

            if not dest_device:
                
                if pkt.fcf_destaddrmode == 0:
                    # Destination address not present
                    dest_device = Device(coord=1, pancoord=1, panid=pkt.dest_panid)
                else:
                    # Destination address present
                    dest_device = Device(addr16 =  (pkt.fcf_destaddrmode == 2) and pkt.dest_addr or None,
                                         addr64 = (pkt.fcf_destaddrmode == 3) and pkt.dest_addr or None, 
                                         panid = pkt.dest_panid)
                    
                self.register_device(dest_device)                    
                    

            # Then, store transmission wth parameters
            self.register_transmission(src_device, dest_device, pkt, frametype=1,
                                       security_enabled=pkt.fcf_security, 
                                       frame_version=pkt.fcf_framever,
                                       security_policy=pkt.aux_sec_header.sec_sc_seclevel if (pkt.fcf_framever and pkt.fcf_security) else None,
                                       srcaddrmode=pkt.fcf_srcaddrmode, destaddrmode=pkt.fcf_destaddrmode)
            

        elif pkt.fcf_frametype == 2:

            print "Ack received / Dropped"
            
            return

        elif pkt.fcf_frametype == 3:


            if pkt.cmd_id == 1:
                
                print "Association request received !"
                
                # Store coordinator address if it is the short one 
                if pkt.fcf_destaddrmode == 2:
                    self.associations_buffer[pkt.src_addr.__str__()] = pkt.dest_addr

                src_device = self.search_device(pkt.src_panid, pkt.src_addr)

                if not src_device:

                    src_device = Device(addr64 = (pkt.fcf_srcaddrmode == 3) and pkt.src_addr or None, 
                                        panid = pkt.dest_panid)
                    
                    self.register_device(src_device)

                dest_device = self.search_device(pkt.dest_panid, pkt.dest_addr)

                if not dest_device:
                    
                    dest_device = Device(addr16 = (pkt.fcf_destaddrmode == 2) and pkt.dest_addr or None,
                                        addr64 = (pkt.fcf_destaddrmode == 3) and pkt.dest_addr or None, 
                                        panid = dest_panid)
                    
                    self.register_device(dest_device)

                self.register_transmission(src_device, dest_device, pkt, frametype=3, framesubtype=1, security_enabled=pkt.fcf_security,
                                           frame_version=pkt.fcf_framever, 
                                           security_policy=pkt.aux_sec_header.sec_sc_level if (pkt.fcf_framever and pkt.fcf_security) else None,
                                           srcaddrmode=pkt.fcf_srcaddrmode, destaddrmode=pkt.fcf_destaddrmode)

            elif pkt.cmd_id == 2:
            
                print "Association response received !"

                panid = pkt.dest_panid 
                masteraddr16 = self.associations_buffer.pop(pkt.dest_addr.__str__(), None)
                masteraddr64 = pkt.src_addr
                slaveaddr64 = pkt.dest_addr

                if not pkt.fcf_security and pkt.association_status == 0:  # Successful
                    slaveaddr16 = pkt.short_address

                # Master addressing informations 
                master1 = self.search_device(panid, masteraddr64)

                if masteraddr16:
                    master2 = self.search_device(panid, masteraddr16)
                else:
                    master2 = None
                    
                if master1 and master2:
                    
                    if master1 != master2:
                        self.merge_devices(master1, master2)
                    master = master1

                elif master1:
                    
                    self.update_device(master1, addr16=masteraddr16)
                    master = master1

                elif master2:
                    
                    self.update_device(master2, addr64=masteraddr64)
                    master = master2

                else:

                    master = Device(addr16=masteraddr16, addr64=masteraddr64, panid=panid)
                    self.register_device(master)

                # Slave addressing informations     
                slave1 = self.search_device(panid, slaveaddr64)

                if slaveaddr16:
                    slave2 = self.search_device(panid, slaveaddr16)
                else:
                    slave2 = None
                    
                if slave1 and slave2:
                    
                    if slave1 != slave2:
                        self.merge_devices(slave1, slave2)
                    slave = slave1

                elif slave1:

                    self.update_device(slave1, addr16=slaveaddr16)
                    slave = slave1
                
                elif slave2:
                    
                    self.update_device(slave1, addr64=slaveaddr64)
                    slave = slave2

                else:
                    slave = Device(addr16=slaveaddr16, addr64=slaveaddr64, panid=panid)
                    self.register_device(slave)

                self.register_transmission(master, slave, pkt, frametype=3, framesubtype=2, security_enabled=pkt.fcf_security,
                                           frame_version=pkt.fcf_framever, 
                                           security_policy=pkt.aux_sec_header.sec_sc_level if (pkt.fcf_framever and pkt.fcf_security) else None,
                                           srcaddrmode=pkt.fcf_srcaddrmode, destaddrmode=pkt.fcf_destaddrmode)

                
            elif pkt.cmd_id == 3:

                print "Disassociation notification receievd !"
                
            elif pkt.cmd_id == 4:

                print "Data request received !"
            
            elif pkt.cmd_id == 5:

                print "PAN ID conflict notification received !"
                
            elif pkt.cmd_id == 6:

                print "Orphan notification received !"
                
            elif pkt.cmd_id == 7:  # No useful information in a beacon request packet"
                print "Beacon request received ! Packet dropped" 
                return

            elif pkt.cmd_id == 8:

                print "Coordinator realignment received !" 

            elif pkt.cmd_id == 9:

                print "GTS request received !" 

            else:

                print "Unknown command packet! Dropped !"
                return
                
