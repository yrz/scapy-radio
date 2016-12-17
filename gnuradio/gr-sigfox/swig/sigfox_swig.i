/* -*- c++ -*- */

#define SIGFOX_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "sigfox_swig_doc.i"

%{
#include "sigfox/packet_sink_scapy.h"
#include "sigfox/preamble_prefixer_scapy.h"
%}


%include "sigfox/packet_sink_scapy.h"
GR_SWIG_BLOCK_MAGIC2(sigfox, packet_sink_scapy);
%include "sigfox/preamble_prefixer_scapy.h"
GR_SWIG_BLOCK_MAGIC2(sigfox, preamble_prefixer_scapy);
