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


SEARCH_EOB = 0
FOUND_EOB = 1


class len_tagger(gr.sync_block):
    """
    docstring for block len_tagger
    """
    def __init__(self):
        gr.sync_block.__init__(self,
            name="len_tagger",
            in_sig=[numpy.complex64],
            out_sig=[numpy.complex64])
        self.set_tag_propagation_policy( 0 ) 

    def work(self, input_items, output_items):
        self.state = SEARCH_EOB
        out = output_items[0]
        in0 = input_items[0]
        
        out[:] = in0[:] #memcpy

        nread = self.nitems_read(0) #number of items read on port 0
        ninput_items = len(in0)

        #read all tags associated with port 0 for items in this work function
        tags = self.get_tags_in_range(0, nread, nread + ninput_items)
        
        num_items = min(len(in0), len(out))
         
        
        for tag in tags:
            if tag.key == pmt.string_to_symbol("tx_eob"):
                self.state = FOUND_EOB
            else:
                self.add_item_tag(0, tag.offset, tag.key, tag.value, pmt.string_to_symbol("len_tagger"))

        if self.state == FOUND_EOB:
            item_index = num_items #which output item gets the tag?
            offset = self.nitems_written(0) + item_index
            key = pmt.string_to_symbol("tx_eob")
            
            source = pmt.string_to_symbol("")
            self.add_item_tag(0, offset - 1, key, pmt.PMT_T, source)

        return len(out)

