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
#include "preamble_prefixer_scapy_impl.h"
#include <string.h>
#include <gnuradio/block_detail.h>
#define SIGFOX 0x06
#define PREAMBLE_SIZE 3
namespace gr {
  namespace sigfox {

    preamble_prefixer_scapy::sptr
    preamble_prefixer_scapy::make()
    {
      return gnuradio::get_initial_sptr
        (new preamble_prefixer_scapy_impl());
    }

    /*
     * The private constructor
     */
    preamble_prefixer_scapy_impl::preamble_prefixer_scapy_impl()
      : gr::block("sigfox_preamble",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0))
    {
	int i = 0;
	for(;i<PREAMBLE_SIZE;i++) preamble[i]=0x55; //inversion of preamble 0xAA;
	message_port_register_out(pmt::mp("out"));
	message_port_register_in(pmt::mp("in"));
	set_msg_handler(pmt::mp("in"),
	boost::bind(&preamble_prefixer_scapy_impl::make_frame, this, _1));
    }

    /*
     * Our virtual destructor.
     */
    preamble_prefixer_scapy_impl::~preamble_prefixer_scapy_impl()
    {
    }

    void
    preamble_prefixer_scapy_impl::make_frame (pmt::pmt_t msg)
    {
	//message empty
	if(pmt::is_eof_object(msg)){
		message_port_pub(pmt::mp("out"),pmt::PMT_EOF);
		detail().get()->set_done(true);
		return;
	}
	//check message
	assert(pmt::is_pair(msg));	//true if the object is pair; permit to catch an error if there is an error it terminates the program
        pmt::pmt_t blob = pmt::cdr(msg); //give a pointer on the second element; => transform into blob = binary large object

	size_t data_len = pmt::blob_length(blob); //size of data
	//assert(data_len);
        //assert(data_len < 33 - 1);

	unsigned char temp[33];
    	std::memcpy(temp, pmt::blob_data(blob), data_len); //copy each byte in temp
	if(temp[0] == SIGFOX){ //check if the corresponding paquet

		std::memcpy(preamble + PREAMBLE_SIZE, (unsigned char*) pmt::blob_data(blob)+8, data_len-8); // copy in preamble[PREAMBLE_SIZE] the data after 8 bytes add in scapy;

		int i = 3;
		for(;i<33;i++) preamble[i]=~preamble[i];

		pmt::pmt_t packet = pmt::make_blob(preamble, PREAMBLE_SIZE +data_len-8);
	        message_port_pub(pmt::mp("out"), pmt::cons(pmt::PMT_NIL, packet)); //send paquet

	}
    }

  } /* namespace sigfox */
} /* namespace gr */

