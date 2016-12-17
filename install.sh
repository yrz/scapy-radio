#!/bin/bash

# Copyright (C) Airbus Defence and Space.
# Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan-Christofer Demay.


check_deps() {
  echo "Checking dependencies ..."
  echo -ne " - Python2.7 :    "; which python2.7 > /dev/null && echo "Found" || { echo "Missing package 'python2.7'"; err=1; }
  echo -ne " - Gnuradio :     "; which grcc > /dev/null && echo "Found" || { echo "Missing package 'gnuradio'"; err=1; }
  echo -ne " - Gnuradio-dev : "; [ -d /usr/include/gnuradio ] && echo "Found" || { echo "Missing package 'gnuradio-dev'"; err=1; }
  echo -ne " - Cmake :        "; which cmake > /dev/null && echo "Found" || { echo "Missing package 'cmake'"; err=1; }
  echo -ne " - Doxygen :      "; which doxygen > /dev/null && echo "Found" || { echo "Missing package 'doxygen'"; err=1; }
  echo -ne " - Pkg Config :   "; which pkg-config > /dev/null && echo "Found" || { echo "Missing package 'pkg-config'"; err=1; }
  echo -ne " - SWIG :         "; which swig > /dev/null && echo "Found" || { echo "Missing package 'swig'"; err=1; }

  [ $err ] && exit 1
}


scapy_install() {

  cd scapy && sudo python2 setup.py install && cd ..

##### FIXME
  cd scapy
  sudo cp -R scapy/crypto /usr/local/lib/python2.7/dist-packages/scapy
  cd ..
#####


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
    grc_local_path="/usr/local/share/gnuradio/grc/blocks"
    #Check custom block path in grc.conf
    cat "$grc_conf" | grep "$grc_local_conf" > /dev/null || { echo "ERROR: $grc_local_var is not configured in $grc_conf"; exit; }
  fi
  orig="$(pwd)"
  cd "$1"
  mkdir -p build
  cd build && cmake -Wno-dev -DPythonLibs_FIND_VERSION:STRING="2.7" -DPythonInterp_FIND_VERSION:STRING="2.7" .. && make && sudo make install && sudo ldconfig;
  cd "$orig"
}

blocks_install() {
  for d in gnuradio/*; do
    [ "$d" = "gnuradio/grc" ] && continue
    gr_block_install "$d"
  done
}


usage(){
  cat << END
Usage :
$0 -- Complete ScapyRadio installation
$0 [ scapy | grc | blocks ] -- Choose what to install
     scapy  : Only install a modified version of Scapy (v 2.3.2-dev)
     grc    : Only install Gnuradio signal processing flowgraphs
     blocks : Only install custom Gnuradio blocks (required to run GRC flowgraphs)
END
  exit 1
}


if [ $# -eq 0 ]; then
  check_deps
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
	usage
    esac
    shift
  done
fi
