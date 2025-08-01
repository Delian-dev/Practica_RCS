#!/bin/bash

filter=$(awk 'BEGIN{ORS=" and "} {gsub(/\r/, ""); print}' filters.txt | sed 's/ and $//')

echo "Using capture filter:"
echo "$filter"
echo

tshark -i wlo1 -f "$filter" -w capture.pcap
