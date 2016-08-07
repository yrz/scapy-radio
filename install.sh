#!/bin/bash

# Copyright (C) Airbus Defence and Space.
# Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan-Christofer Demay.

scapy_install() {
  cd scapy && sudo python2 setup.py install && cd ..
}

grc_install() {
  mkdir -p "${HOME}/.scapy/radio/"

  for i in gnuradio/grc/*.grc; do
    mkdir -p "${HOME}/.scapy/radio/$(basename ${i} .grc)"
    cp "${i}" "${HOME}/.scapy/radio/"
    grcc --directory="${HOME}/.scapy/radio/$(basename ${i} .grc)" "${i}"
  done
}

gr_block_install() {
  if [ -z $PREFIX ] || [ $PREFIX = "/usr/local" ]; then
    grc_conf="/etc/gnuradio/conf.d/grc.conf"
    grc_local_var="local_blocks_path"
    grc_local_path="/usr/local/share/gnuradio/grc/blocks"
    grc_local_val=$(IFS="="; grep $grc_local_var $grc_conf | while read -r name value; do echo "${value//\ /}"; done)
    if [ "$grc_local_val" != "$grc_local_path" ]; then
      echo ERROR: $grc_local_var is not configured to $grc_local_path in $grc_conf
      exit
    fi
  fi
  orig="$(pwd)"
  cd "$1"
  mkdir -p build
  cd build && cmake -Wno-dev -DPythonLibs_FIND_VERSION:STRING="2.7" -DPythonInterp_FIND_VERSION:STRING="2.7" .. && make && sudo make install
  cd "$orig"
}

blocks_install() {
  for d in gnuradio/*; do
    [ "$d" = "gnuradio/grc" ] && continue
    gr_block_install "$d"
  done
}

if [ $# -eq 0 ]; then
  scapy_install
  blocks_install
  grc_install
else
  while [ $# -ne 0 ]; do
    case $1 in
      scapy)
	scapy_install
	;;
      grc)
	grc_install
	;;
      blocks)
	blocks_install
	;;
      *)
	echo "Invalid option: $1"
    esac
    shift
  done
fi
