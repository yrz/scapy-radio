#!/bin/sh
export VOLK_GENERIC=1
export GR_DONT_LOAD_PREFS=1
export srcdir=/home/pentest/Downloads/scapy-radio/gnuradio/gr-wmbus/python
export PATH=/home/pentest/Downloads/scapy-radio/gnuradio/gr-wmbus/python:$PATH
export LD_LIBRARY_PATH=/home/pentest/Downloads/scapy-radio/gnuradio/gr-wmbus/lib:$LD_LIBRARY_PATH
export PYTHONPATH=/home/pentest/Downloads/scapy-radio/gnuradio/gr-wmbus/swig:$PYTHONPATH
/usr/bin/python2 /home/pentest/Downloads/scapy-radio/gnuradio/gr-wmbus/python/qa_packet_sink.py 
