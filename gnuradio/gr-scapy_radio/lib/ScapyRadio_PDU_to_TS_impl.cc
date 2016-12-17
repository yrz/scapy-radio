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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "ScapyRadio_PDU_to_TS_impl.h"
#include <gnuradio/block_detail.h>
#include <unistd.h>
#include <gnuradio/buffer.h>

namespace gr {
  namespace scapy_radio {

    ScapyRadio_PDU_to_TS::sptr
    ScapyRadio_PDU_to_TS::make(std::string tag, int usleep, bool debug)
    {
      return gnuradio::get_initial_sptr
        (new ScapyRadio_PDU_to_TS_impl(tag, usleep, debug));
    }

    /*
     * The private constructor
     */
    ScapyRadio_PDU_to_TS_impl::ScapyRadio_PDU_to_TS_impl(std::string tag, int usleep, bool debug)
      : gr::block("ScapyRadio_PDU_to_TS",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(1, 1, sizeof(gr_complex)))
    {
      message_port_register_in(pmt::mp("in"));
      set_msg_handler(pmt::mp("in"), boost::bind(&ScapyRadio_PDU_to_TS_impl::callback, this, _1));
      set_tag_propagation_policy(gr::block::TPP_DONT);

      gr::block::set_min_output_buffer(200000);
      burst_tag = tag;
      delay = (usleep > 0) ? 0 : usleep;
      dbg = (debug) ? true : false;
    }

    /*
     * Our virtual destructor.
     */
    ScapyRadio_PDU_to_TS_impl::~ScapyRadio_PDU_to_TS_impl()
    {
    }

    void
    ScapyRadio_PDU_to_TS_impl::forecast (int noutput_items, gr_vector_int &ninput_items_required)
    {
      ninput_items_required[0] = 0; //Fool scheduler
    }

    int
    ScapyRadio_PDU_to_TS_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
      usleep(delay);
      return 0;
    }


    void
    ScapyRadio_PDU_to_TS_impl::callback(pmt::pmt_t msg)
    {

//Init
      gr_complex* in_data_ptr = NULL;
      gr_complex* out = NULL;

//Verif data
      if(! pmt::is_pair(msg)) {
        if(dbg) printf("[SND1] Bad INPUT message (not pair CAR,CDR)\n");
        return; //Bad MSG input
      }

//Get data
      pmt::pmt_t blob = pmt::cdr(msg);
      gr_complex* in_data = (gr_complex*)pmt::blob_data(blob);
      in_data_len = (int)(pmt::blob_length(blob) / sizeof(gr_complex));


//Tags
      block_out_ptr = detail()->output(0);
      gr::block::add_item_tag(0, nitems_written(0), pmt::string_to_symbol(burst_tag.c_str()), pmt::from_long(in_data_len), pmt::string_to_symbol(alias()));


      if (dbg) printf("[%s] Sent : %d samples\n", alias().c_str(), in_data_len);

//Send data
      gr_complex* block_out_buffer = (gr_complex*)block_out_ptr->write_pointer();

      gr_complex zob[200000];

      memcpy(zob, in_data, in_data_len * sizeof(gr_complex));
      memcpy(block_out_buffer, zob, in_data_len * sizeof(gr_complex));
      block_out_ptr->update_write_pointer(in_data_len);

      return;


    }

  } /* namespace scapy_radio */
} /* namespace gr */

