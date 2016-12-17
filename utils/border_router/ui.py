from socket import *
from scapy.layers.dot15d4 import *
from scapy.layers.inet import *


def check_ndp_table(ndp_table, my_ipv6):

    if ndp_table.get(my_ipv6) != None:

        if ndp_table.get(my_ipv6).get('panid') == None:

            print "Panid missing for ipv6 address %s ! Please add an entry to user_ndp_table if you want to use this ipv6 address" % my_ipv6
            print "Exiting program"
            exit()

        elif not is_panid_valid(ndp_table.get(my_ipv6)['panid']):
            print "Panid for ipv6 address %s is invalid! Check the format" % my_ipv6
            print "Exiting program"
            exit()

        if ndp_table.get(my_ipv6).get('long') == None and ndp_table.get(my_ipv6).get('short') == None:

            print " Link-layer short and long addresses missing for ipv6 address %s ! At least one of them shall be available" % my_ipv6
            print "Exiting program"
            exit()

        if ndp_table.get(my_ipv6).get('long') != None:

            if not is_longaddr_valid(ndp_table.get(my_ipv6)['long']):
                print "Extended 64-bit address for ipv6 address %s is invalid! Check the format" % my_ipv6
                print "Exiting program"
                exit()

        if ndp_table.get(my_ipv6).get('short') != None:

            if not is_shortaddr_valid(ndp_table.get(my_ipv6)['short']):
                print "Short 16-bit address for ipv6 address %s is invalid! Check the format" % my_ipv6
                print "Exiting program"
                exit()
            
    else:

        print "Link-layer addressing information missing for ipv6 address %s ! Please add an entry to user_ndp_table or use the Scanner_802_15_4 to generate a database" % my_ipv6
        print "Exiting program"
        exit()

        
def ui_choose_channel():

    while 1:

        channel = input('Please provide the channel you wish the border router to run on : (11 - 26) : ')

        try:

            channel = int(channel)

            if channel < 11 or channel > 26:
                print " 11 <= channel <=  26 !! "

            else:
                return channel

        except:

            print "Wrong format"


def ui_choose_database():

    while 1:

        path = raw_input('If you want to use a Dot15d4 Database provide the path, otherway just press Enter : ')

        if path != '':

            if load_dot15d4_database(path):

                conf.dot15d4use_database = 1
                conf.dot15d4auto_secure = 1
                conf.dot15d4auto_unsecure = 1
                
                print path + " loaded successfully!"

                return

            else:

                print 'Wrong path'

        else:

            print 'No Dot15d4 database will be used'
            return
    
            
def ui_choose_ipv6_addr():

    while 1:

        print
        
        my_ipv6 = raw_input("Please provide the IPv6 address you want your computer to use : (format exemple fe80::1234:5678 ) : ")

        try:

            socket.inet_pton(socket.AF_INET6, my_ipv6)
            return my_ipv6

        except:

            print "Wrong format"


def is_panid_valid(panid):

    if type(panid) != int:
        return False

    if panid > 0xffff:
        return False

    if panid < 0:
        return False

    return True


def is_shortaddr_valid(addr):

    if type(addr) != int:
        return False

    if addr > 0xffff:
        return False

    if addr < 0:
        return False
            
    return True

    
def is_longaddr_valid(addr):

    if type(addr) != int and type(addr) != long:
        return False

    if addr > 0xffffffffffffffff:
        return False

    if addr < 0:
        return False

    return True
