#!/bin/bash
device_ip="$1"
pcap_file=$2
output_pcap=$3
timestamp_file=$4
gap=$5
duration=$6
filter="ip.addr==$device_ip&&ip.len>200"
tshark -w $output_pcap -r $pcap_file -Y $filter
python3 packet_analyzer.py $device_ip $output_pcap $timestamp_file $gap $duration
