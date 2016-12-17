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
#include "wmbus_packet_sink_impl.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstring>
#include <gnuradio/blocks/count_bits.h>
#include <iostream>
#include <string>

namespace gr {
  namespace wmbus {

    wmbus_packet_sink::sptr
    wmbus_packet_sink::make(int param_mode, bool debug)
    {
      return gnuradio::get_initial_sptr
        (new wmbus_packet_sink_impl(param_mode, debug));
    }

    /*
     * The private constructor
     */
    wmbus_packet_sink_impl::wmbus_packet_sink_impl(int mod, bool debug)
      : gr::block("wmbus_packet_sink",
              gr::io_signature::make(1, 1, sizeof(char)),
              gr::io_signature::make(0, 0, 0))
    {
    //Parameters
      dbg = debug;
      param_mode = mod;

    //Init state machine
      state = PREAMBLE_SEARCH;
      if (dbg) printf("[State] PREAMBLE_SEARCH\n");
      frame_shift_reg = 0;
      bit_count = 0;
      preamble_len = 0;
      message_port_register_out(pmt::mp("out"));
    }

    /*
     * Our virtual destructor.
     */
    wmbus_packet_sink_impl::~wmbus_packet_sink_impl()
    {}

    void
    wmbus_packet_sink_impl::forecast (int noutput_items, gr_vector_int &ninput_items_required)
    {}

    int
    wmbus_packet_sink_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
      const unsigned char *inbuf = (const unsigned char*)input_items[0];
      int ninput = ninput_items[0];
      int count = 0;

      while(count < ninput){
        switch(state){


          /*************************************************************
          //                  STATE 1 : Preamble Search
          *************************************************************/
          case PREAMBLE_SEARCH : //Looking for Preable & count len
          while (count < ninput) {

            frame_shift_reg = frame_shift_reg << 1 | (inbuf[count++] & 1);
            bit_count++;

            if (bit_count/4){ // every 4 bits
              if ((frame_shift_reg & 0xF) != 0xf){ //Not 0xF

                if((frame_shift_reg & 0xF) == 0x5 || (frame_shift_reg & 0xF) == 0xA){ //0x5 or 0xA
                  preamble_len++;
                }else{ //SyncWord ?

                  if (preamble_len > 4){ //Preamble OK => next state
                    preamble_len*=2; // 1*0x5 = 1*0101 = 2*01 => real preable len
                    state=SYNC_WORD_SEARCH;
                    if (dbg) printf("\n[RCV] Preamble len :%d\n[RCV] [State] SW_SEARCH\n",preamble_len);
                    break;
                  }
                  preamble_len=0;
                  frame_shift_reg=0;

                }
              }

              bit_count=0;
            }

          }
          break;



          /*************************************************************
          //                  STATE 2 : Sync Word Search
          *************************************************************/
          case SYNC_WORD_SEARCH :      //Looking for sync word if found go to next state
          while (count < ninput) {

            if (bit_count > 40){
              if (dbg) printf("[RCV] SyncWord Timeout !\n");
              reset();
              break;
            }


            //Sync word T found
            if (param_mode != 1 && mode == C && bit_count == 4 && (frame_shift_reg & 0xF) == 0xD ) { //if next nibble == 0xD then mode = C
              
              frame_shift_reg = 0; //reset shift register
              state = GET_LEN;
              if (dbg) printf("[RCV] [State] GET_LEN\n");

              if (param_mode == 2){
                mode=C;
                if (dbg) printf("\n[RCV] Mode C\n");
              }else{
                mode=C2C;
                if (dbg) printf("\n[RCV] Mode C2C\n");
              }

              bit_count=0;
              frame_struct.len=8;
              break;

            }


            if(param_mode == 1 && (frame_shift_reg & 0x0003FFFF) == 0x00007696){ //Sync word S found
              frame_shift_reg = 0; //reset shift register
              state = GET_LEN;
              mode = S;

              if (dbg) printf("[RCV] [State] GET_LEN\n[RCV] Mode S\n");
              bit_count = 0;
              frame_struct.len = 8;
              break;

            }else if(param_mode != 1 && (frame_shift_reg & 0x0003FF) == 0x03D){ //Sync word C OR T found
              frame_shift_reg = 0; //reset shift register
              state = GET_LEN;
              mode = CorT;

              if (dbg) printf("[RCV] [State] GET_LEN\n[RCV] Mode T/C\n");
              bit_count = 0;
              frame_struct.len = 8;
              break;
            }

            frame_shift_reg = frame_shift_reg << 1 | (inbuf[count++] & 1);
            bit_count++;

          }
          break;





          /*************************************************************
          //                  STATE 3 : Get Packet Length Byte
          *************************************************************/
          case GET_LEN :

            ///////////////////////// Mode S
            if (mode == S){


              while (count < ninput) {
                frame_shift_reg = frame_shift_reg << 1 | (inbuf[count++] & 1);
                bit_count++;

                if (bit_count/16){ // 4 nibbles
                  frame_len = decode_manchester(frame_shift_reg & 0xFFFF);
                  if (frame_len < 16 || frame_len > 256){
                    if (dbg) printf("Bad len : %02x\n",frame_len);
                    reset();
                    break;
                  }
                  frame_struct.frame[ frame_struct.len ] = frame_len;
                  frame_struct.len++;
//CALCUL CRC LEN !!!! A REMETTRE !!!!
                  frame_len += 2 * calc_num_crc(frame_len); //1 Len byte + 2*nbr_of_crc
                  frame_len++;
                  
                  state = READ_DATA;
                  if (dbg) printf("[RCV] Len packet = %d Bytes\n[RCV] [State] READ_DATA\n",frame_len);
                  bit_count=0;
                  break;
                }
              }


            ///////////////////////// Mode C
            } else if (mode == C || mode == C2C) {


              while (count < ninput) {
                frame_shift_reg = frame_shift_reg << 1 | (inbuf[count++] & 1);
                bit_count++;

                if (bit_count/8){ // 2 nibbles

                  frame_len = frame_shift_reg & 0xFF;
                  if (frame_len < 16 || frame_len > 256){
                    reset();
                    break;
                  }
                  frame_struct.frame[ frame_struct.len ] = frame_len;
                  frame_struct.len++;
                  frame_len += 1 + 2 * calc_num_crc(frame_len); //1 Len byte + 2*nbr_of_crc

                  state = READ_DATA;
                  if (dbg) printf("[RCV] Len packet = %d Bytes\n[RCV] [State] READ_DATA\n",frame_len);
                  bit_count=0;
                  break;
                }
              }


            ///////////////////////// Mode C/T
            } else if (mode == CorT) {


              while (count < ninput) {
                frame_shift_reg = frame_shift_reg << 1 | (inbuf[count++] & 1);
                bit_count++;

                if (bit_count/12){ // 3 nibbles
                  bit_count=0;

                  if (dbg) printf("[RCV] Preamble : %08x\n",(frame_shift_reg & 0xFFF));
                  if ((frame_shift_reg & 0xFFF) == 0x54C){ //Mode C - Frame type A
                    mode = C;
                    frame_type = TYPE_A;
                    state = SYNC_WORD_SEARCH;
                    if (dbg) printf("[RCV] C frame A ?\n[RCV] [State] SW_SEARCH\n");
                    break;

                  }else if ((frame_shift_reg & 0xFFF) == 0x543){ //Mode C - Frame type B
                    mode = C;
                    frame_type = TYPE_B;
                    state = SYNC_WORD_SEARCH;
                    if (dbg) printf("[RCV] C frame B ?\n[RCV] [State] SW_SEARCH\n");
                    break;

                  }else{ //Mode T or bad sync word

                    mode=T;
                    frame_len = decode_3to6(frame_shift_reg & 0xFFF);
                    if (frame_len < 16 || frame_len > 256){
                      reset();
                      break;
                    }
                    frame_struct.frame[ frame_struct.len ] = frame_len;
                    frame_struct.len ++;
                    frame_len += 1 + 2 * calc_num_crc(frame_len); //1 Len byte + 2*nbr_of_crc

                    state = READ_DATA;
                    if (dbg) printf("[RCV] Len packet = %d Bytes\n[RCV] [State] READ_DATA\n",frame_len);
                    bit_count=0;
                    break;
                  }

                }
              }


            }
          break;







          /*************************************************************
          //                  STATE 4 : Read Packet Payload
          *************************************************************/
          case READ_DATA :

            ///////////////////////// Mode S
            if (mode == S){
              while (count < ninput) {


                frame_shift_reg = frame_shift_reg << 1 | (inbuf[count++] & 1);
                bit_count++;

                if (bit_count/16){ // 8 nibbles -> 1 decoded byte
                  bit_count = 0;

                  frame_struct.frame[ frame_struct.len ] = decode_manchester(frame_shift_reg & 0xFFFF);
                  frame_struct.len++;

                  if((frame_struct.len) == frame_len + 8 ){

                    pmt::pmt_t meta = pmt::make_dict();
                    craft_GR_Header();
                    pmt::pmt_t payload = pmt::make_blob(frame_struct.frame, (frame_struct.len));
                    message_port_pub(pmt::mp("out"), pmt::cons(meta, payload));

                    //Reset state machine
                    reset();
                    break;
                  }

                }
              }


            ///////////////////////// Mode T/C
            } else if(mode==T){
              while (count < ninput) {


                frame_shift_reg = frame_shift_reg << 1 | (inbuf[count++] & 1);
                bit_count++;

                if (bit_count/12){ // 3 nibbles
                  bit_count=0;
                  frame_struct.frame[ frame_struct.len ] = decode_3to6(frame_shift_reg & 0xFFF);
                  frame_struct.len++;

                  if((frame_struct.len) == frame_len + 8){

                    pmt::pmt_t meta = pmt::make_dict();
                    craft_GR_Header();
                    pmt::pmt_t payload = pmt::make_blob(frame_struct.frame, (frame_struct.len));
                    message_port_pub(pmt::mp("out"), pmt::cons(meta, payload));

                    //Reset state machine
                    reset();
                    break;
                  }

                }
              }


            ///////////////////////// Mode C
            } else if(mode==C || mode == C2C){ //Mode T/C
              while (count < ninput) {


                frame_shift_reg = frame_shift_reg << 1 | (inbuf[count++] & 1);
                bit_count++;

                if (bit_count/8){ // 2 nibbles
                  bit_count=0;
                  frame_struct.frame[ frame_struct.len ] = (frame_shift_reg & 0xFFF);
                  frame_struct.len++;

                  if((frame_struct.len) == frame_len + 8){

                    pmt::pmt_t meta = pmt::make_dict();
                    craft_GR_Header();
                    pmt::pmt_t payload = pmt::make_blob(frame_struct.frame, (frame_struct.len));
                    message_port_pub(pmt::mp("out"), pmt::cons(meta, payload));

                    //Reset state machine
                    reset();
                    break;
                  }
                }

              }

            }
          break;


        } //EndSwitch
      } //EndMainLoop

      consume(0, ninput_items[0]);
      return 0;
    }


    unsigned char wmbus_packet_sink_impl::decode_3to6(int input){
      unsigned char output=0;
      int temp=input;
      bool error=true;
      unsigned char table[16]={ 0x16, 0x0D, 0x0E, 0x0B, 0x1C, 0x19, 0x1A, 0x13, 0x2C, 0x25, 0x26, 0x23, 0x34, 0x31, 0x32, 0x29 };
      
      for (char a=0; a < 2; a++){ //Loop for 0x0000 0011 1111 & 0x1111 1100 0000
        for (char i=0; i < 16; i++){
          if ( table[i] == (input & 0x3F) ){
            output = (output >> 4) | (i << 4);
            input = input >> 6;
            error=false;
            break;
          }
        }
        if (error){
          if (dbg) printf("[RCV] 3->6 error : %04x \n",temp);
          return 0x00; //Truc à faire j'pense
        }
      }


      return output;
    }

    unsigned char wmbus_packet_sink_impl::decode_manchester(int input){
      unsigned char output=0;
      bool error=true;
      unsigned char table[16]={ 0xAA, 0xA9, 0xA6, 0xA5, 0x9A, 0x99, 0x96, 0x95, 0x6A, 0x69, 0x66, 0x65, 0x5A, 0x59, 0x56, 0x55};
      int save=input;
      for (char a=0; a < 2; a++){ //Loop for 0x00FF & 0xFF00
        for (char i=0; i < 16; i++){
          if ( table[i] == (input & 0xFF) ){
            output = (output >> 4) | (i << 4);
            input = input >> 8;
            error=false;
            break;
          }
        }
        if (error){
          if (dbg) printf("[RCV] Manchester error : %04x \n",save);
          return 0x00;
        }
      }
      return output;
    }



    unsigned char wmbus_packet_sink_impl::calc_num_crc(int len){
      unsigned char nbr_crc=0;

      if (frame_type==TYPE_A){        //Type A
        (len >= 9)?(nbr_crc++):0;
        nbr_crc += (len-9)/16;
        ((len-9)%16)?(nbr_crc++):0;
      }else{                          //Type B
        //nbr_crc=(len <= 125)?1:2;
        nbr_crc=0;
        if (dbg) printf("[RCV] CRCs : %d",nbr_crc);
      }
      return nbr_crc;
    }


    void wmbus_packet_sink_impl::craft_GR_Header(void){
      memset(GRH,0,8);

      GRH[0] = 0x4;                 //Proto = WMBus
      GRH[2] = mode;                //Channel
      GRH[4] = frame_type & 1;      //Protocol related info : frame type
      //preamble_len=15;
      GRH[5] = ( preamble_len / 4); //Protocol related info : Preamble len

      memcpy(frame_struct.frame, GRH, 8);
      return;
    }


    void wmbus_packet_sink_impl::reset(void){ //Reset state machine

      frame_shift_reg=0;
      preamble_len=0;
      bit_count=0;
      mode=S;
      if (dbg) printf("[RCV] [State] PREAMBLE_SEARCH (Reset)\n");
      state = PREAMBLE_SEARCH;
      return;
    }






  } /* namespace wmbus */
} /* namespace gr */

