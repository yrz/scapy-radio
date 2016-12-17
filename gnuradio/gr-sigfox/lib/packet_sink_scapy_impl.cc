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
#include "packet_sink_scapy_impl.h"
#include <iostream>

#define SIGFOX 0x06 //Select Sigfox

namespace gr {
  namespace sigfox {

    packet_sink_scapy::sptr
    packet_sink_scapy::make()
    {
      return gnuradio::get_initial_sptr
        (new packet_sink_scapy_impl());
    }

    /*
     * The private constructor
     */
    packet_sink_scapy_impl::packet_sink_scapy_impl()
      : gr::block("Sigfox_packet",				//name of the custom block
              gr::io_signature::make(1, 1, sizeof(char)),	//input signature
              gr::io_signature::make(0, 0, 0))			//output signature
    {
	buf[0] = SIGFOX;
        buf[1] = 0x00; //Unused
        buf[2] = 0x00; //Unused
        buf[3] = 0x00; //Unused
        buf[4] = 0x00; //Unused
        buf[5] = 0x00; //Unused
        buf[6] = 0x00; //Unused
        buf[7] = 0x00; //Unused

	state = PREAMBLE_SEARCH;
    	cpt = 0; //compteur
	frame_shift_reg = 0x000000; // 32 bits
    	taille = 0x00;
	frame = 0x00;
	paquet = 0;
	i=10; // 8 bytes for scapy header and 2 octets for sync_word
        sous_taille = true;
	message_port_register_out(pmt::mp("out")); //name of output port
    }

    packet_sink_scapy_impl::~packet_sink_scapy_impl()
    {
    }

    void
    packet_sink_scapy_impl::forecast (int noutput_items, gr_vector_int &ninput_items_required)
    {
    }

    int
    packet_sink_scapy_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
        const unsigned char *inbuf = (const unsigned char *) input_items[0]; //on caste un tableau de type void en tableau de caractere sur 8 bits
	int ninput = ninput_items[0]; //size of input buffer
	int count=0;
	while(count < ninput){
	    switch(state){
        	case PREAMBLE_SEARCH :      //Looking for preamble if found go to next state
			while (count < ninput) {
				//update the shift register
                		if(inbuf[count++])  frame_shift_reg = frame_shift_reg << 1;    //shift of 1 bit to add a 0  --> inversion to prohibit chunks to symbols
                       		else frame_shift_reg = (frame_shift_reg << 1)  | 1 ;//shift of 1 bit to add a 1
				//looking for preamble in the first byte with sync_word associate
				if((frame_shift_reg & 0xFFFF) == 0xA08D){ //detection of 4 bits of preamble, sync_word and sous_taille: payload = 1 octet
                 			var = 0x1;
					state = DATA;
					paquet = (int) var + 11 + 10; //nos 10 octets header + sync_word and 11 bytes of frame without payload (temporary 5 bytes of CRC)
					buf[8] = 0x00;
					buf[9] = 0x8D;
					break;
				}
				if((frame_shift_reg & 0xFFFF) == 0xA35F){ //payload = 2 to 4 bytes
					var = 0x00;
					state = DATA;
					buf[8] = 0x03;
                                        buf[9] = 0x5F;
					break;
				}
				if((frame_shift_reg & 0xFFFF) == 0xA611){ //payload = 5 to 8 bytes
                                        var = 0x04;
					state = DATA;
					buf[8] = 0x06;
                                        buf[9] = 0x11;
					break;
				}
				if((frame_shift_reg & 0xFFFF) == 0xA94C){ //payload = 9 to 12 bytes
                                        var = 0x08;
                                        state = DATA;
					buf[8] = 0x09;
                                        buf[9] = 0x4C;
                                        break;
				}
			}
               	break;
		case DATA : //send rest of data temporary
			while (count < ninput) {
				//update the shift register
                                if(inbuf[count++]) frame = frame << 1;
				else frame = (frame << 1)  | 1 ;
				cpt++;
				if (sous_taille == true && cpt == 2){ //detection of sous_taille on 2 bits
					sous_taille = false;
					if((var == 0x1 & frame != 0b00000000) | (var == 0x00 & frame == 0b00000011)){ //wrong detection
                                                state = PREAMBLE_SEARCH;
                                                cpt = 0;
                                                frame = 0x00;
						sous_taille = true;
                                                break;
                                        }
                                        if(var != 0x1){ //calculation of size of paquet
                                                taille = ~frame & 0b00000011;
                                                var = (var | taille) + 0b00000001;
                                                paquet = (int) var + 11 +10; //10 bytes (header + sync_word); 11 bytes of frame (5 bytes of CRC)
                                        }
				}
				if (cpt == 8){ //1 byte complete to store
					cpt = 0;
					buf[i] = frame;
					frame=0x00;
					i++;
				}
				if(i==paquet){ //paquet complete (5 bytes of CRC) <- to fix when we know the exact size of CRC 
					pmt::pmt_t meta = pmt::make_dict();
					pmt::pmt_t payload = pmt::make_blob(buf, paquet); //number of bytes in array to read;
                                        message_port_pub(pmt::mp("out"), pmt::cons(meta,payload)); //cons(key,value)
					i = 10;
					sous_taille = true;
					state = PREAMBLE_SEARCH;
					break;
				}
			}
		break;
	     }//end switch
	} //end  while
        consume(0, ninput_items[0]);//consume_each (noutput_items);
        // Tell runtime system how many output items we produced.
        return 0;//noutput_items;
    }
  } /* namespace sigfox */
} /* namespace gr */

