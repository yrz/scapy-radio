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

#ifndef INCLUDED_SIGFOX_PREAMBLE_PREFIXER_SCAPY_IMPL_H
#define INCLUDED_SIGFOX_PREAMBLE_PREFIXER_SCAPY_IMPL_H

#include <sigfox/preamble_prefixer_scapy.h>

namespace gr {
  namespace sigfox {

    class preamble_prefixer_scapy_impl : public preamble_prefixer_scapy
    {
     private:
      // Nothing to declare in this block.
	unsigned char preamble[33];
     public:
      preamble_prefixer_scapy_impl();
      ~preamble_prefixer_scapy_impl();

      // Where all the action really happens
      void make_frame(pmt::pmt_t msg);
    };

  } // namespace sigfox
} // namespace gr

#endif /* INCLUDED_SIGFOX_PREAMBLE_PREFIXER_SCAPY_IMPL_H */

