/* -*- c++ -*- */

#define WMBUS_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "wmbus_swig_doc.i"

%{
#include "wmbus/wmbus_preamble.h"
#include "wmbus/wmbus_packet_sink.h"
%}


%include "wmbus/wmbus_preamble.h"
GR_SWIG_BLOCK_MAGIC2(wmbus, wmbus_preamble);

%include "wmbus/wmbus_packet_sink.h"
GR_SWIG_BLOCK_MAGIC2(wmbus, wmbus_packet_sink);
