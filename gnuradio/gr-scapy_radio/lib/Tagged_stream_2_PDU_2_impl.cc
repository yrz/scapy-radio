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
#include "Tagged_stream_2_PDU_2_impl.h"

namespace gr {
  namespace scapy_radio {

    Tagged_stream_2_PDU_2::sptr
    Tagged_stream_2_PDU_2::make(std::string first_t, std::string last_t, int buff_size, bool debug)
    {
      return gnuradio::get_initial_sptr
        (new Tagged_stream_2_PDU_2_impl(first_t, last_t, buff_size, debug));
    }

    /*
     * The private constructor
     */
    Tagged_stream_2_PDU_2_impl::Tagged_stream_2_PDU_2_impl(std::string first_t, std::string last_t, int b_len, bool debug)
      : gr::block("Tagged_stream_2_PDU_2",
              gr::io_signature::make(1, 1, sizeof(gr_complex)),
              gr::io_signature::make(0, 0, 0))
    {
      message_port_register_out(pmt::mp("out"));
      d_pdu_meta = pmt::make_dict(); //Init tag dict

      start_tag = first_t;
      end_tag = last_t;
      buffer_len = b_len;
      dbg = (debug) ? true : false;
      big = (gr_complex *)calloc(buffer_len, sizeof(gr_complex));
      if ( ! big ){
        printf("[SND2] %d Bytes allocation failed\n",buffer_len);
        assert(big);
      }

      action=0; //wait for start


      if (dbg) printf("[SND2] Packet tag triggers : <%s> Packet <%s>\n[SND2] Buffer size : %d samples\n",start_tag.c_str(), end_tag.c_str(), buffer_len);
      //init data array
      curr_ptr = big;
      curr_len = 0;
    }


    Tagged_stream_2_PDU_2_impl::~Tagged_stream_2_PDU_2_impl()
    {
      if ( big ) free(big);
    }

    void
    Tagged_stream_2_PDU_2_impl::forecast (int noutput_items, gr_vector_int &ninput_items_required)
    {}

    int
    Tagged_stream_2_PDU_2_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
//Init
      const gr_complex *inbuf = (const gr_complex*) input_items[0];
      int ninput = ninput_items[0];
      int count = 0;

//Get tags for current buffer window
      get_tags_in_range(d_tags, 0, nitems_read(0), nitems_read(0) + ninput_items[0] );



      for (d_tags_itr = d_tags.begin(); d_tags_itr != d_tags.end(); d_tags_itr++) { //Foreach tags

        if ( (*d_tags_itr).key == pmt::string_to_symbol(start_tag.c_str()) ){
          if (dbg) printf("[SND2] Start of burst found @offset : %d\n",(*d_tags_itr).offset);
          curr_ptr=big;
          curr_len=0;
          action=(action | 0x1); //Fill Buffer
        }else if ( (*d_tags_itr).key == pmt::string_to_symbol(end_tag.c_str()) ){
          ninput = (*d_tags_itr).offset - nitems_read(0); //Get number of samples before end tag
          if (dbg) printf("[SND2] End of burst found @offset : %d\n",(*d_tags_itr).offset);
          action=0x3; //Fill Buffer + Send
        } else {
          d_pdu_meta = dict_add(d_pdu_meta, (*d_tags_itr).key, (*d_tags_itr).value); //Propagate other tags
        }

      }
      
      if (action & 0x1) push_buffer(inbuf, ninput);
      if (action & 0x2) send_buffer();
   

//Like a sink
      consume(0, ninput_items[0]);
      return 0;
    }



    void Tagged_stream_2_PDU_2_impl::push_buffer(const gr_complex * inbuf, int ninput){
      if ( (ninput + curr_len) > buffer_len ){
        printf("[SND2] Overflow : %d samples dropped ! Consider increasing buffer size.",buffer_len);
        action=0;
      }
      else{
        memcpy(curr_ptr, inbuf, ninput * sizeof(gr_complex));
        curr_ptr += ninput;
        curr_len += ninput;
      }
      return;
    }



    void Tagged_stream_2_PDU_2_impl::send_buffer(void){

      if(dbg) printf("[SND2] %d samples sent\n",curr_len);

      pmt::pmt_t packet = pmt::init_c32vector(curr_len, (const gr_complex *)big);
      message_port_pub(pmt::mp("out"), pmt::cons(d_pdu_meta, packet));
      d_pdu_meta = pmt::make_dict(); //Reset dict



//Reset & Return
      curr_ptr=big;
      curr_len=0;
      action=0;
      return;
    }



  } /* namespace scapy_radio */
} /* namespace gr */

