#!/usr/bin/python2

# Copyright (C) Airbus Defence and Space
# Authors: Adam Reziouk, Jean-Michel Huguet, Jonathan-Christofer Demay

## This program is free software; you can redistribute it and/or modify it 
## under the terms of the GNU General Public License version 3 as
## published by the Free Software Foundation.
##
## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details

from scapy.all import *

# A buffer used to store Sixlowpan Fragments
class sixlowpan_frag_buf:
    
    def deco_full(self,size, first_off):
        def f(off):
            return (off == (size - first_off))
        return f

    def deco_ovf(self,size, first_off):
        def f(off):
            return (off > (size - first_off))
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
        
    #def order_by_offset(self):
    #    Define a function whi-ch order the list of fragrmented element using offset
    
    def __init__(self, p):        

        # Exceptions 
        self.not_subsequent_except = self.SixlowpanFragBufError("You are updating a sixlowpan_frag_buf with a wrong packet")
        self.not_first_except = self.SixlowpanFragBufError("You are instanciating a sixlowpan_frag_buf with a wrong packet")
        self.ovf_except = self.SixlowpanFragBufError("sixlowpan_frag_buf overflow: there is more data than expected")
        self.full_except = self.SixlowpanBufferFull()

        cls = LoWPANFragmentationFirst
        # Check if it is a Sixlowpan Fragmentation First pkt 
        if cls not in p:
            raise self.not_first_except
        self.plist = [p]
        self.size = p[LoWPANFragmentationFirst].datagramSize
        self.offset = len(p[LoWPANFragmentationFirst].payload)
        self.first_frag_offset = 0
        self.frag_byte_copied = 0
        
    # Overload of the left-shift operator: "sixlowpan_frag_buf_X << packet" adds the packet 
    # in the "plist" attribute and update the "offset" attribute. Then a exception is raised if 
    # the buffer is full (all the intended fragmented frames have been received).
    def __lshift__(self, p):        

        cls = LoWPANFragmentationSubsequent
        if cls not in p:
            raise self.not_subsequent_except

        self.plist.append(p)
        
        self.frag_offset = p.datagramOffset * 8

        if not self.first_frag_offset:
            self.first_frag_offset = self.frag_offset
            self.buffer_full = self.deco_full(self.size, self.first_frag_offset)
            self.buffer_overflow = self.deco_ovf(self.size, self.first_frag_offset)

        self.frag_byte_copied += len(p[LoWPANFragmentationSubsequent].payload)  # 5 is the length of the LoWPANFragmentationSubsequent dispatch


        if self.buffer_overflow(self.frag_byte_copied):
            raise self.ovf_except

        elif self.buffer_full(self.frag_byte_copied):
            raise self.full_except            


    def __str__(self):
        str_plist = ""
        for p in self.plist:
            str_plist += str(p)
            str_plist += '\n'
        return str_plist

