#!/bin/bash

# Arg1 should point to the folder with YourThings traces (PCAP files w/o any expected events).
# There are 3 overlap devices:
# 1) Belkin WeMo switch: https://yourthings.info/devices/belkin_switch.html
# 2) Roomba iRobot 690: https://yourthings.info/devices/roomba.html
# 3) TP-Link Bulb LB130: https://yourthings.info/devices/tplink_bulb.html
YT_TRACES_DIR=$1

# Arg2 should point to the base directory  for signature files (i.e., /some/local/path/experimental_result/standalone)
SIGNATURES_BASE_DIR=$2
readonly SIGNATURES_BASE_DIR

# Arg3 should point to base directory where the detection results for the UNSW trace are to be output.
# Subfolders will be created for each individual pcap file in YT_TRACES_DIR.
OUTPUT_DIR=$3
readonly OUTPUT_DIR

#set -x # echo invoked commands to std out

# Download and untar the public data set https://yourthings.info/data/
# Then everything should be untarred/unzipped into /.../2018/
# YT_TRACES_DIR path should be something like /.../2018/
# Then there are subfolders inside 2018/ such as 2018/03/20/
for SUBFOLDER1 in $YT_TRACES_DIR/*; do
	for SUBFOLDER2 in $SUBFOLDER1/*; do
		for PCAP_FILE in $SUBFOLDER2/*; do
            # skip non pcap files
            [ -e "$PCAP_FILE" ] || continue
            # make an output sub dir in the base output dir that is the filename minus extension
            OUTPUT_SUB_DIR=$(basename "$PCAP_FILE" .pcap)
            ./execute_layer2_unb_all_detection.sh $PCAP_FILE $SIGNATURES_BASE_DIR $OUTPUT_DIR/$OUTPUT_SUB_DIR
		done
	done
done