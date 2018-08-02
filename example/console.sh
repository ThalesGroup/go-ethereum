#!/bin/bash

if [ "$#" -ne 1 ]; then
  echo "usage: ./console.sh <node>"
  exit
fi

docker exec -it geth$1 geth attach /etc/geth/data/geth.ipc
