#!/bin/bash

# TODO: This script was used to look for certain IP addresses in the YourThings public dataset.
# TODO: https://yourthings.info/

# Arg1 should point to the folder with YourThings traces (PCAP files w/o any expected events).
# There are 3 overlap devices:
# 1) Belkin WeMo switch: https://yourthings.info/devices/belkin_switch.html
# 2) Roomba iRobot 690: https://yourthings.info/devices/roomba.html
# 3) TP-Link Bulb LB130: https://yourthings.info/devices/tplink_bulb.html
YT_TRACES_DIR=$1

# Arg2 should contain the IP address that we are looking for in a certain PCAP file
IP_ADDRESS=$2

# Arg3 should point to output file that has the list of PCAP files that contain a certain IP address.
# Subfolders will be created for each individual pcap file in YT_TRACES_DIR.
OUTPUT_FILE=$3

# Download and untar the public data set https://yourthings.info/data/
# Then everything should be untarred/unzipped into /.../2018/
# YT_TRACES_DIR path should be something like /.../2018/
# Then there are subfolders inside 2018/ such as 2018/03/20/
for SUBFOLDER1 in $YT_TRACES_DIR/*; do
	for SUBFOLDER2 in $SUBFOLDER1/*; do
		for PCAP_FILE in $SUBFOLDER2/*; do
			# skip non pcap files
			[ -e "$PCAP_FILE" ] || continue
			RESULT=`tshark -r $PCAP_FILE | grep $IP_ADDRESS`
			echo $PCAP_FILE
			# make an output sub dir in the base output dir that is the filename minus extension
			if [ -n "$RESULT" ]; then
                #OUTPUT_SUB_DIR=$(basename "$PCAP_FILE" .pcap)
                echo "$IP_ADDRESS is found in this PCAP file!"
                echo $PCAP_FILE >> $OUTPUT_FILE
            fi
		done
	done
done
