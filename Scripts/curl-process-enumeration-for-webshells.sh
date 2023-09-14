#/bin/bash

command_file=$1
for cmd in $(cat ${command_file}); do
    curl -s -6 -X POST "http://[IPV6]:80/" -H "Cookie: PHPSESSID=IDNUM" -d "command=${cmd}" | grep -q "Command is not allowed."
    if [ $? -eq 1 ]; then
        echo -e "  \e[42m${cmd}\e[49m allowed";
    else
        echo -e "  \e[41m${cmd}\e[49m blocked";
    fi;
done

#By 0xdf
#Create a list with the commands you want to test and give as argument
