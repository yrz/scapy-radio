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


#ifndef INCLUDED_DOT15D4_PREAMBLE_PREFIXER_SCAPY_H
#define INCLUDED_DOT15D4_PREAMBLE_PREFIXER_SCAPY_H

#include <dot15d4/api.h>
#include <gnuradio/block.h>

namespace gr {
  namespace dot15d4 {

    /*!
     * \brief <+description of block+>
     * \ingroup dot15d4
     *
     */
    class DOT15D4_API preamble_prefixer_scapy : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<preamble_prefixer_scapy> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of dot15d4::preamble_prefixer_scapy.
       *
       * To avoid accidental use of raw pointers, dot15d4::preamble_prefixer_scapy's
       * constructor is in a private implementation
       * class. dot15d4::preamble_prefixer_scapy::make is the public interface for
       * creating new instances.
       */
      static sptr make();
    };

  } // namespace dot15d4
} // namespace gr

#endif /* INCLUDED_DOT15D4_PREAMBLE_PREFIXER_SCAPY_H */

