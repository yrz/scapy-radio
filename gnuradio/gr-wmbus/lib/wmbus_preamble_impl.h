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

#ifndef INCLUDED_WMBUS_WMBUS_PREAMBLE_IMPL_H
#define INCLUDED_WMBUS_WMBUS_PREAMBLE_IMPL_H

#include <wmbus/wmbus_preamble.h>

namespace gr {
  namespace wmbus {

    class wmbus_preamble_impl : public wmbus_preamble
    {
     private:
      buffer_sptr block_out_ptr;
      enum mode_t {S, T, C, C2C} mode;
      enum frame_type_t {TYPE_A, TYPE_B} frame_type;
      unsigned int preamble_len;
      size_t in_data_len;
      size_t out_data_len_cod;
      size_t out_data_len_total;
      unsigned int sync_word;
      unsigned char out_buff[700];
      int delay;
      bool dbg;

     public:
      wmbus_preamble_impl(int usleep, bool debug);
      ~wmbus_preamble_impl();

      // Where all the action really happens
      void forecast (int noutput_items, gr_vector_int &ninput_items_required);

      int general_work(int noutput_items,
		       gr_vector_int &ninput_items,
		       gr_vector_const_void_star &input_items,
		       gr_vector_void_star &output_items);
      void callback(pmt::pmt_t msg);
      unsigned char * parse_strip_GR_Header(unsigned char * data);
      void code_manchester(unsigned char src, int i, unsigned char* dst);
      void code_3to6(unsigned char * in, int in_len, unsigned char * out);
      
    };

  } // namespace wmbus
} // namespace gr

#endif /* INCLUDED_WMBUS_WMBUS_PREAMBLE_IMPL_H */

