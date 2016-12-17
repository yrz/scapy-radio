/* -*- c++ -*- */

#define DOT15D4_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "dot15d4_swig_doc.i"

%{
#include "dot15d4/packet_sink_scapy.h"
#include "dot15d4/preamble_prefixer_scapy.h"
%}


%include "dot15d4/packet_sink_scapy.h"
GR_SWIG_BLOCK_MAGIC2(dot15d4, packet_sink_scapy);
%include "dot15d4/preamble_prefixer_scapy.h"
GR_SWIG_BLOCK_MAGIC2(dot15d4, preamble_prefixer_scapy);
