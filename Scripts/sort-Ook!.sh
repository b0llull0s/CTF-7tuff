#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: $0 [infile] [outfile]"
    exit 1
fi

input_file="$1"
output_file="$2"

if ! [[ -f "$input_file" ]]; then
    echo "Input file does not exist: $input_file"
    exit 1
fi

sed 's/\./Ook. /g; s/?/Ook? /g; s/!/Ook! /g' "$input_file" > "$output_file"

if [ $? -eq 0 ]; then
    echo "Conversion successful. Output saved in $output_file"
else
    echo "Conversion failed."
fi
