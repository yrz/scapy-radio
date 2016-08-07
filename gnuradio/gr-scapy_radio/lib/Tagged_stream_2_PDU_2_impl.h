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

#ifndef INCLUDED_SCAPY_RADIO_TAGGED_STREAM_2_PDU_2_IMPL_H
#define INCLUDED_SCAPY_RADIO_TAGGED_STREAM_2_PDU_2_IMPL_H

#include <scapy_radio/Tagged_stream_2_PDU_2.h>

namespace gr {
  namespace scapy_radio {

    class Tagged_stream_2_PDU_2_impl : public Tagged_stream_2_PDU_2
    {
     private:
      pmt::pmt_t           d_pdu_meta;
      pmt::pmt_t           d_pdu_vector;
      std::vector<tag_t>::iterator d_tags_itr;
      std::vector<tag_t>   d_tags;
      unsigned char action;
      std::string start_tag;
      std::string end_tag;
      bool dbg;
      int buffer_len;

      //Data handling
      gr_complex *big;
      unsigned int curr_len;
      gr_complex* curr_ptr;
      unsigned char wait_for_start;


     public:
      Tagged_stream_2_PDU_2_impl(std::string first_t, std::string last_t, int buff_size, bool debug);
      ~Tagged_stream_2_PDU_2_impl();

      // Where all the action really happens
      void forecast (int noutput_items, gr_vector_int &ninput_items_required);

      int general_work(int noutput_items,
           gr_vector_int &ninput_items,
           gr_vector_const_void_star &input_items,
           gr_vector_void_star &output_items);

      void push_buffer(const gr_complex * inbuf, int ninput);
      void send_buffer(void);
    };

  } // namespace scapy_radio
} // namespace gr

#endif /* INCLUDED_SCAPY_RADIO_TAGGED_STREAM_2_PDU_2_IMPL_H */

