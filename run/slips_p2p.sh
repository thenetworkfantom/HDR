#!/bin/bash

if [ -z "$*" ]; then
  echo "Usage: <script> <interface/file>";
  exit 1;
fi

interface_list=()

for interface in $(ip link show | awk -F': ' '{print $2}' | sed '/lo/d'); do
  interface_list+=("$interface")
done

if [[ " ${interface_list[*]} " == *" ${1} "* ]]; then
  docker run -it -d --rm --name slips --net=host -p 55000:55000 -v $(pwd)/output:/StratosphereLinuxIPS/output -v $(pwd)/config:/StratosphereLinuxIPS/config stratosphereips/slips_p2p ./slips.py -e 1 -i ${1}
else
  exho "invalid interface."
fi

