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


#ifndef INCLUDED_SIGFOX_PREAMBLE_PREFIXER_SCAPY_H
#define INCLUDED_SIGFOX_PREAMBLE_PREFIXER_SCAPY_H

#include <sigfox/api.h>
#include <gnuradio/block.h>

namespace gr {
  namespace sigfox {

    /*!
     * \brief <+description of block+>
     * \ingroup sigfox
     *
     */
    class SIGFOX_API preamble_prefixer_scapy : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<preamble_prefixer_scapy> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of sigfox::preamble_prefixer_scapy.
       *
       * To avoid accidental use of raw pointers, sigfox::preamble_prefixer_scapy's
       * constructor is in a private implementation
       * class. sigfox::preamble_prefixer_scapy::make is the public interface for
       * creating new instances.
       */
      static sptr make();
    };

  } // namespace sigfox
} // namespace gr

#endif /* INCLUDED_SIGFOX_PREAMBLE_PREFIXER_SCAPY_H */

