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
import string

DEBUG=1

class uhd_tags(gr.sync_block):
    """
    docstring for block uhd_tags
    """





    def __init__(self, len_tag, start_tag, end_tag):
        gr.sync_block.__init__(self,
            name="uhd_tags",
            in_sig=[numpy.byte],
            out_sig=[numpy.byte])
        self.set_tag_propagation_policy(0)
        self.len_tag = len_tag
        self.start_tag = start_tag
        self.end_tag = end_tag



    def work(self, input_items, output_items):
        in0 = input_items[0]
        out = output_items[0]
        out[:] = in0[:]


        nread = self.nitems_read(0) #number of items read on port 0
        ninput_items = len(in0)

        sob_t = pmt.string_to_symbol(self.start_tag)
        eob_t = pmt.string_to_symbol(self.end_tag)
        len_t = pmt.string_to_symbol(self.len_tag)

        value = pmt.from_bool(1)
        source = pmt.string_to_symbol("uhd_tags")

        tags = self.get_tags_in_range(0, nread, nread+ninput_items)
        for tag in tags:

            #print "key : " + str(tag.key)
            if str(tag.key) == self.len_tag:

                if DEBUG:
                    print "Found burst start at offset : " + str(tag.offset) + " with len : " + str(tag.value)
                    print " -> Injecting tag "+ self.start_tag +" @" + str(tag.offset)
                    print " -> Injecting tag "+ self.end_tag +" @" + str(tag.offset + pmt.to_long(tag.value) -1)
                self.add_item_tag(0, tag.offset, sob_t, value, source)
                self.add_item_tag(0, tag.offset + pmt.to_long(tag.value) -1, eob_t, value, source)



        return len(out)

