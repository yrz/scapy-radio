/* -*- c++ -*- */
/* 
 * Copyright 2016 <+YOU OR YOUR COMPANY+>.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef INCLUDED_HOWTO_SIGFOX_PACKET_IMPL_H
#define INCLUDED_HOWTO_SIGFOX_PACKET_IMPL_H

#include <sigfox/packet_sink_scapy.h>

namespace gr {
  namespace sigfox {

    class packet_sink_scapy_impl : public packet_sink_scapy
    {
     private:
      // Nothing to declare in this block.
	enum {PREAMBLE_SEARCH, DATA, CRC_HMAC} state;
        unsigned int frame_shift_reg;
        unsigned char buf[33]; //array of 33 bytes to store paquet
	unsigned char var;
     	unsigned int paquet;
	unsigned char frame;
	unsigned char taille;
	unsigned int cpt;
	unsigned int i;
	bool sous_taille;
      public:
      packet_sink_scapy_impl();
      ~packet_sink_scapy_impl();
      // Where all the action really happens
      void forecast (int noutput_items, gr_vector_int &ninput_items_required);
      int general_work(int noutput_items,
		       gr_vector_int &ninput_items,
		       gr_vector_const_void_star &input_items,
		       gr_vector_void_star &output_items);
    };

  } // namespace howto
} // namespace gr

#endif /* INCLUDED_HOWTO_SIGFOX_PACKET_IMPL_H */

