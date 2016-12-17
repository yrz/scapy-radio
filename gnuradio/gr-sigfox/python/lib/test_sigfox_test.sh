#!/bin/sh
export VOLK_GENERIC=1
export GR_DONT_LOAD_PREFS=1
export srcdir=/home/pentest/Downloads/scapy-radio/gnuradio/gr-sigfox/lib
export PATH=/home/pentest/Downloads/scapy-radio/gnuradio/gr-sigfox/python/lib:$PATH
export LD_LIBRARY_PATH=/home/pentest/Downloads/scapy-radio/gnuradio/gr-sigfox/python/lib:$LD_LIBRARY_PATH
export PYTHONPATH=$PYTHONPATH
test-sigfox 
