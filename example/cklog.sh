#!/bin/bash

if [ "$#" -ne 1 ]; then
  echo "usage: ./cklog.sh <node>"
  exit
fi

docker exec -it geth$1 tail -f /tmp/cklog.txt
