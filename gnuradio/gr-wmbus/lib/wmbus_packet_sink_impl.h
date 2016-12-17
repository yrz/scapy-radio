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

#ifndef INCLUDED_WMBUS_WMBUS_PACKET_SINK_IMPL_H
#define INCLUDED_WMBUS_WMBUS_PACKET_SINK_IMPL_H

#include <wmbus/wmbus_packet_sink.h>

#define MAX_FRAME_SIZE 263 //frame size not pdu

namespace gr {
  namespace wmbus {

    class wmbus_packet_sink_impl : public wmbus_packet_sink
    {
     private:
      enum {PREAMBLE_SEARCH, SYNC_WORD_SEARCH, GET_LEN, READ_DATA} state;
      enum {S, T, C, C2C, CorT} mode;
      enum { SHORT_HEADER, LONG_HEADER} header_type;
      enum {TYPE_A, TYPE_B} frame_type;
        int param_mode;
        unsigned int frame_shift_reg;
        unsigned int bit_count;
        unsigned char frame_len;
        unsigned short preamble_len;
        unsigned char GRH[8];
        bool dbg;
        struct s_frame_struct
        {
            unsigned int len;
            unsigned char frame[MAX_FRAME_SIZE];
        };
        struct s_frame_struct  frame_struct;

     public:
      wmbus_packet_sink_impl(int param_mode, bool debug);
      ~wmbus_packet_sink_impl();

      // Where all the action really happens
      void forecast (int noutput_items, gr_vector_int &ninput_items_required);

      int general_work(int noutput_items,
		       gr_vector_int &ninput_items,
		       gr_vector_const_void_star &input_items,
		       gr_vector_void_star &output_items);

      unsigned char decode_3to6(int input);
      unsigned char decode_manchester(int input);
      unsigned char calc_num_crc(int len);
      void reset(void);
      void craft_GR_Header(void);
    };

  } // namespace wmbus
} // namespace gr

#endif /* INCLUDED_WMBUS_WMBUS_PACKET_SINK_IMPL_H */

