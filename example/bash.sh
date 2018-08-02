#!/bin/bash

if [ "$#" -ne 1 ]; then
  echo "usage: ./bash.sh <node>"
  exit
fi

docker exec -it geth$1 bash
