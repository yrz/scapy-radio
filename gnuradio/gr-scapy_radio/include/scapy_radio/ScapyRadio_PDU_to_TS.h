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


#ifndef INCLUDED_SCAPY_RADIO_SCAPYRADIO_PDU_TO_TS_H
#define INCLUDED_SCAPY_RADIO_SCAPYRADIO_PDU_TO_TS_H

#include <scapy_radio/api.h>
#include <gnuradio/block.h>

namespace gr {
  namespace scapy_radio {

    /*!
     * \brief <+description of block+>
     * \ingroup scapy_radio
     *
     */
    class SCAPY_RADIO_API ScapyRadio_PDU_to_TS : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<ScapyRadio_PDU_to_TS> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of scapy_radio::ScapyRadio_PDU_to_TS.
       *
       * To avoid accidental use of raw pointers, scapy_radio::ScapyRadio_PDU_to_TS's
       * constructor is in a private implementation
       * class. scapy_radio::ScapyRadio_PDU_to_TS::make is the public interface for
       * creating new instances.
       */
      static sptr make(std::string tag, int usleep, bool debug);
    };

  } // namespace scapy_radio
} // namespace gr

#endif /* INCLUDED_SCAPY_RADIO_SCAPYRADIO_PDU_TO_TS_H */

