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

#ifndef INCLUDED_SCAPY_RADIO_SCAPYRADIO_PDU_TO_TS_IMPL_H
#define INCLUDED_SCAPY_RADIO_SCAPYRADIO_PDU_TO_TS_IMPL_H

#include <scapy_radio/ScapyRadio_PDU_to_TS.h>

namespace gr {
  namespace scapy_radio {

    class ScapyRadio_PDU_to_TS_impl : public ScapyRadio_PDU_to_TS
    {
     private:
      buffer_sptr block_out_ptr;
      size_t in_data_len;
      int delay;
      bool dbg;
      std::string burst_tag;

     public:
      ScapyRadio_PDU_to_TS_impl(std::string tag, int usleep, bool debug);
      ~ScapyRadio_PDU_to_TS_impl();

      // Where all the action really happens
      void forecast (int noutput_items, gr_vector_int &ninput_items_required);

      int general_work(int noutput_items,
           gr_vector_int &ninput_items,
           gr_vector_const_void_star &input_items,
           gr_vector_void_star &output_items);

      void callback(pmt::pmt_t msg);
    };

  } // namespace scapy_radio
} // namespace gr

#endif /* INCLUDED_SCAPY_RADIO_SCAPYRADIO_PDU_TO_TS_IMPL_H */

