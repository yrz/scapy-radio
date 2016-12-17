from scapy.all import *

# A buffer used to store Sixlowpan Fragments
class sixlowpan_frag_buf:
    
    def deco_full(self,size, first_off):
        def f(off):
            return (off == (size - first_off))
        return f

    class SixlowpanFragBufError(Exception):
        def __init__(self, message):
            self.message = message
        def __str__(self):
            return repr(self.message)

    class SixlowpanBufferFull(Exception):
        def __init__(self):
            self.message = "Buffer is full: handle it"
        def __str__(self):
            return repr(self.message)
            
    def __init__(self, p):        

        # Exceptions 
        self.full_except = self.SixlowpanBufferFull()
        self.timeout = 60
        
        self.plist = [p]

        self.datagram_size = p.datagramSize

        self.processed_ipv6_len = 0
        
        if LoWPANFragmentationFirst in p:

            if LoWPAN_IPHC in p:

                if LoWPAN_UDP in p:
                    self.processed_ipv6_len = len(p[LoWPAN_UDP].payload) + 48
                else:
                    self.processed_ipv6_len = len(p[LoWPAN_IPHC].payload) + 40

            elif p[LoWPANFragmentationFirst].payload[0] == '\x41':
                # Uncompressed IPv6
                self.processed_ipv6_len = len(p[LoWPANFragmentationFirst].payload)
            else:
                # Not a 6LoWPAN pkt, discard pkt
                self.timeout = 0
                print "Wrong Fragment! Not a sixlowpan pkt! Discaring link fragments"

        else:

            self.processed_ipv6_len = len(p[LoWPANFragmentationSubsequent].payload)
            
    # Overload of the left-shift operator: "sixlowpan_frag_buf_X << packet" adds the packet 
    # in the "plist" attribute and update the "offset" attribute. Then a exception is raised if 
    # the buffer is full (all the intended fragmented frames have been received).

    def __lshift__(self, p):

        if LoWPANFragmentationFirst in p:

            for pkt in self.plist:

                if LoWPANFragmentationFirst in pkt:
                    # Discard pkt
                    self.timeout = 0
                    print "Fragmentation First packet received twice! Discaring link fragments"
                    return

            if LoWPAN_IPHC in p:

                if LoWPAN_UDP in p:
                    self.processed_ipv6_len += len(p[LoWPAN_UDP].payload) + 48
                else:
                    self.processed_ipv6_len += len(p[LoWPAN_IPHC].payload) + 40

            elif p[LoWPANFragmentationFirst].payload[0] == '\x41':
                # Uncompressed IPv6
                self.processed_ipv6_len += len(p[LoWPANFragmentationFirst].payload)
            else:
                # Not a 6LoWPAN pkt, discard pkt
                self.timeout = 0
                print "Wrong Fragment! Not a sixlowpan pkt! Discaring link fragments"
                
        else:  # Subsequent fragment

            for pkt in self.plist:

                if LoWPANFragmentationSubsequent in pkt and pkt.datagramOffset == p.datagramOffset:
                    self.timeout = 0
                    print "Subsequent packet received twice! Discaring link fragments"
                    return

            self.processed_ipv6_len += len(p[LoWPANFragmentationSubsequent].payload)


        self.plist.append(p)  # Add pkt to pkt list

        if self.processed_ipv6_len == self.datagram_size:

            first = None

            for pkt in self.plist:
                if LoWPANFragmentationFirst in pkt:
                    first = pkt
                    break

            if first == None:
                print "No first fragment received! Discaring link fragments"
                self.timeout = 0
                return 

            else:

                # Temporary remove first fragment from list
                self.plist.remove(first)

                # Sort fragment by offset
                sorted(self.plist, key=lambda n: n.datagramOffset)

                # Reinsert first frag into list
                self.plist.insert(0, first)
            
                raise self.full_except
                
        elif self.processed_ipv6_len > self.datagram_size:
            
            print "fragmented data size does not match datagramSize! Discaring pkt!"
            self.timeout = 0
            return

