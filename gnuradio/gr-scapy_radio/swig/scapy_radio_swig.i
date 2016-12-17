/* -*- c++ -*- */

#define SCAPY_RADIO_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "scapy_radio_swig_doc.i"

%{
//#include "scapy_radio/add_gr_header.h"
//#include "scapy_radio/strip_gr_header.h"
#include "scapy_radio/Tagged_stream_2_PDU_2.h"
#include "scapy_radio/ScapyRadio_PDU_to_TS.h"
%}


//%include "scapy_radio/add_gr_header.h"
//GR_SWIG_BLOCK_MAGIC2(scapy_radio, add_gr_header);
//%include "scapy_radio/strip_gr_header.h"
//GR_SWIG_BLOCK_MAGIC2(scapy_radio, strip_gr_header);
%include "scapy_radio/Tagged_stream_2_PDU_2.h"
GR_SWIG_BLOCK_MAGIC2(scapy_radio, Tagged_stream_2_PDU_2);
%include "scapy_radio/ScapyRadio_PDU_to_TS.h"
GR_SWIG_BLOCK_MAGIC2(scapy_radio, ScapyRadio_PDU_to_TS);
