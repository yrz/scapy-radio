#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
# Copyright 2016 <+YOU OR YOUR COMPANY+>.
# 
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
# 
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this software; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
# 

import numpy
from gnuradio import gr
import pmt
import time

class add_uhd_tag(gr.sync_block):
    """
    docstring for block add_uhd_tag
    """
    def __init__(self):
        gr.sync_block.__init__(self,
            name="add_uhd_tag",
            in_sig=[numpy.byte],
            out_sig=[numpy.byte])
        self.set_tag_propagation_policy(0)



    def work(self, input_items, output_items):
        in0 = input_items[0]
        out = output_items[0]
        out[:] = in0[:]


        nread = self.nitems_read(0) #number of items read on port 0
        ninput_items = len(in0)

        eob = pmt.string_to_symbol("tx_eob")
        sob = pmt.string_to_symbol("tx_sob")
        pan = pmt.string_to_symbol("pdu_length")
        value = pmt.from_bool(1)
        lng = pmt.from_long(8192)
        source = pmt.string_to_symbol("add_uhd_tag")

        tags = self.get_tags_in_range(0, nread, nread+ninput_items)
        print "total input items : " + str(ninput_items)
        for tag in tags:

            #print "key : " + str(tag.key)
            if str(tag.key) == "pdu_length":

                #print "Found burst start at offset : " + str(tag.offset) + " with value : " + str(tag.value)
                #print " -> Injecting tag tx_sob @" + str(tag.offset)
                #print " -> Injecting tag tx_eob @" + str(tag.offset + pmt.to_long(tag.value) -1)
                self.add_item_tag(0, tag.offset, sob, value, source)
                self.add_item_tag(0, tag.offset + pmt.to_long(tag.value) -1, eob, value, source)



        return len(out)

