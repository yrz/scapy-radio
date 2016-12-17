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

import pmt
import numpy
from gnuradio import gr

sauvegarde = 0 
last_freq = 0
i = 0

class Detection_Peak(gr.basic_block):
    """
    docstring for block Detection_Peak
	threshold: when we obtain a new frequency, this frequency is send if it is outside of the bandwith [-threshold, threshold]
	scale: permit to obtain the frequency value 
	Becareful: if you change the threshold, you need to modify the filter.   
    """
    def __init__(self, Threshold, Scale):
        gr.basic_block.__init__(self,
            name="Detection_Peak",
            in_sig=[numpy.float32],
            out_sig=[])
	self.seuil = Threshold  # = 90
        self.f = Scale # = 250000/2*pi
        self.message_port_register_out(pmt.intern("out0"))
        self.message_port_register_out(pmt.intern("out1"))
        self.message_port_register_out(pmt.intern("out2"))

    def general_work(self, input_items, output_items):
	in0 = input_items[0]
        global sauvegarde, last_freq, i
        var = round(numpy.median(in0)*self.f)
        if in0.all() != 0 and var > 0 : #buffer different of null
		if ( (abs(sauvegarde - var) > self.seuil) and (abs(last_freq - var) > self.seuil) ):
                        if i == 0 :
				self.message_port_pub(pmt.intern('out0'),pmt.cons(pmt.intern("freq"), pmt.from_double(var)))
                	if i == 1 :
                        	self.message_port_pub(pmt.intern('out1'),pmt.cons(pmt.intern("freq"), pmt.from_double(var)))
                	if i == 2 :
                        	self.message_port_pub(pmt.intern('out2'),pmt.cons(pmt.intern("freq"), pmt.from_double(var)))
			last_freq = sauvegarde
			sauvegarde = var
			i = i+1
			if i == 3: i = 0 

        self.consume(0, len(input_items[0]))
        return len(input_items[0])
