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
#include "wmbus_preamble_impl.h"
#include <gnuradio/block_detail.h>
#include <unistd.h>
#include <gnuradio/buffer.h>

namespace gr {
  namespace wmbus {

    wmbus_preamble::sptr
    wmbus_preamble::make(int usleep, bool debug)
    {
      return gnuradio::get_initial_sptr
        (new wmbus_preamble_impl(usleep, debug));
    }

    /*
     * The private constructor
     */
    wmbus_preamble_impl::wmbus_preamble_impl(int usleep, bool debug)
      : gr::block("wmbus_preamble",
        gr::io_signature::make(0, 0, 0),
        gr::io_signature::make(3, 3, 1))
    {
      message_port_register_in(pmt::mp("Scapy"));
      set_msg_handler(pmt::mp("Scapy"), boost::bind(&wmbus_preamble_impl::callback, this, _1));
      set_tag_propagation_policy(gr::block::TPP_DONT);

      delay = (usleep > 0) ? 0 : usleep;
      dbg = (debug) ? true : false;
    }

    /*
     * Our virtual destructor.
     */
    wmbus_preamble_impl::~wmbus_preamble_impl()
    {
    }

    void
    wmbus_preamble_impl::forecast (int noutput_items, gr_vector_int &ninput_items_required)
    {
      ninput_items_required[0] = 0; //Fool scheduler
    }

    int
    wmbus_preamble_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
      usleep(delay);
      return 0;
    }

    void wmbus_preamble_impl::callback(pmt::pmt_t msg)
    {

//Init
      uint8_t out_num = 0;
      unsigned char * in_data_ptr = NULL;
      unsigned char * out = NULL;


//Verif data
      if(! pmt::is_pair(msg)) {
        if(dbg) printf("[SND1] Bad INPUT message (not pair CAR,CDR)\n");
        return; //Bad MSG input
      }

      pmt::pmt_t blob = pmt::cdr(msg);
      unsigned char* in_data = (unsigned char*)pmt::blob_data(blob);
      in_data_len = pmt::blob_length(blob);


      if( (in_data_len < 9) || (in_data_len > 256) ){ //Bad MSG Len
        if(dbg) printf("[SND1] Bad INPUT data len or empty payload (%d Bytes)\n",in_data_len);
        return;
      }

      in_data_ptr = parse_strip_GR_Header(in_data);
      if (! in_data_ptr){ //Not WMBus => drop
        if(dbg) printf("[SND1] Packet dropped\n");
        return;
      }


//Calc output len after encoding
      if (mode==S) out_data_len_cod = in_data_len*2; //Manchester
      else if (mode == T) {
        out_data_len_cod = ((in_data_len * 3) % 2 )?(in_data_len * 1.5):((in_data_len * 1.5)+1);
      }
      else out_data_len_cod = in_data_len; //NRZ


      preamble_len = (preamble_len%4)?((preamble_len/4)+1):(preamble_len/4);
      out_data_len_total = preamble_len + 4 + out_data_len_cod + 1; //Preamble + SyncWord + Encoded_Data + Padding

      if(dbg) printf("[SND1] Input len: %d\n[SND1] Frame_type: %d\n[SND1] Preamble len: %d\n[SND1] Mode: %d\n[SND1] Sync word: %08x\n[SND1] Output Code len: %d\n",in_data_len,frame_type,preamble_len,mode,sync_word,out_data_len_total);


//Add Preamble
      int i=0;
      out_buff[0]=1;
      for (i=0; i < preamble_len ; i++) out_buff[i] = 0x55; //Preamble

//Add Sync word
      out_buff[i++] = (sync_word & 0xFF000000 ) >> 24;
      out_buff[i++] = (sync_word & 0x00FF0000 ) >> 16;
      out_buff[i++] = (sync_word & 0x0000FF00 ) >> 8;
      out_buff[i++] = (sync_word & 0x000000FF );

//Pointer to start of payload
      out = &out_buff[i];//out = start of payload

//Code + insert payload
      int j=0;
      if (mode==S){
        for (; j < in_data_len ; j++) code_manchester(in_data_ptr[j], j, out); //Manchester
        out_num = 0;
      }
      else if (mode == T) {
        code_3to6(in_data_ptr, in_data_len, out); //strip header
        out_num = 1;
      }
      else for (; i < out_data_len_total - 1; i++,j++){
        out_buff[i]=in_data_ptr[j]; //NRZ
        out_num = 2;
      }

//Padding
      out_data_len_total+=2;
      //out[out_data_len_total] = 0;

//tags
      block_out_ptr = detail()->output(out_num);
      add_item_tag(out_num, nitems_written(out_num), pmt::string_to_symbol("tx_sob"), pmt::PMT_T, pmt::string_to_symbol(alias()));
      add_item_tag(out_num, nitems_written(out_num) + out_data_len_total - 1, pmt::string_to_symbol("tx_eob"), pmt::PMT_T, pmt::string_to_symbol(alias()));



//Send data
      unsigned char* block_out_buffer = (unsigned char*)block_out_ptr->write_pointer();
      memcpy(block_out_buffer,out_buff,out_data_len_total);
      block_out_ptr->update_write_pointer(out_data_len_total);


      return;
    }




    unsigned char * wmbus_preamble_impl::parse_strip_GR_Header(unsigned char * data){

      if (data[0] != 4){
        if(dbg) printf("[SND1] Packet type != WMBus\n");
        return NULL; //Not WMBus => drop.
      }
      unsigned char ext_len = data[7];
      frame_type = (frame_type_t)(data[4] & 1);
      preamble_len = data[5];
      mode = (mode_t)data[2];
      if (mode > 4){
        if(dbg) printf("[SND1] Invalid channel : %d\n",mode);
        return NULL; //Invalid mode => drop.
      }

      if (! preamble_len) preamble_len = 48;
      else preamble_len = (preamble_len * 4) + 48; //Nbr of (01) in preamble

      in_data_len -= (8 + ext_len); //Strip header + ext_header

      if (mode == S) sync_word = ( (0x5554 << 16 ) + 0x7696); // SyncWord + preamble padding
      else if (mode == T) sync_word = ( (0x555554 << 8 ) + 0x3D); // SyncWord + preamble padding
      else if (mode == C || mode == C2C){
        if(frame_type == TYPE_A) sync_word = ( 0x543D54CD ); // SyncWord
        else sync_word = ( 0x543D543D ); // SyncWord
      }

      if (in_data_len <= 0) return NULL; //No payload
      else return &data[(8 + ext_len)];
    }



    void wmbus_preamble_impl::code_manchester(unsigned char in, int i, unsigned char* out){
      unsigned char tab[16] = { 0xAA, 0xA9, 0xA6, 0xA5, 0x9A, 0x99, 0x96, 0x95, 0x6A, 0x69, 0x66, 0x65, 0x5A, 0x59, 0x56, 0x55 };
      out[ i * 2 ] = tab[ in >> 4 ]; //Left most nimble => 1 byte
      out[ i * 2 + 1 ] = tab[ in & 0xF ]; //right most nimble => 1 byte

      return;
    }



    void wmbus_preamble_impl::code_3to6(unsigned char * in, int in_len, unsigned char * out){
        unsigned char * ptr = out;
        unsigned char table[16]={ 0x16, 0x0D, 0x0E, 0x0B, 0x1C, 0x19, 0x1A, 0x13, 0x2C, 0x25, 0x26, 0x23, 0x34, 0x31, 0x32, 0x29 };

        int SR=0; //shift register
        int i = 0;

        for( i=0; i < in_len; i++ ){
          SR = SR << 6;
          SR += table[ (in[i]) >> 4 ]; // 1111 0000 => 4 MSB from input
          SR = SR << 6;
          SR += table[ (in[i]) & 0xF ]; // 0000 1111 => 4 LSB from input

          if( SR & 0xF000 ){ //Register FULL
            *ptr = ( SR & 0xFF00) >> 8;
            ptr ++;
            *ptr = ( SR & 0xFF);
            ptr++;
            SR=0; //Clean SR

          }else{ //REGISTER HALF
            *ptr = (SR & 0xFF0) >> 4;
            ptr++;
            SR = SR & 0xF; //Clean SR
          }
        }

        if( SR ) *ptr = ( SR << 4 ) & 0xFF; //If SR not empty
        *ptr = *ptr + 0x5;

      return;
    }


  } /* namespace wmbus */
} /* namespace gr */

