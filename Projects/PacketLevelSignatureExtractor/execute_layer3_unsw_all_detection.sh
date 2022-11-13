#!/bin/bash

# Arg1 should point to the folder with UNSW traces (PCAP files w/o any expected events).
UNSW_TRACES_DIR=$1

# Arg2 should point to the base directory  for signature files (i.e., /some/local/path/experimental_result/standalone)
SIGNATURES_BASE_DIR=$2
readonly SIGNATURES_BASE_DIR

# Arg3 should point to base directory where the detection results for the UNSW trace are to be output.
# Subfolders will be created for each individual pcap file in UNSW_TRACES_DIR.
OUTPUT_DIR=$3
readonly OUTPUT_DIR

#set -x # echo invoked commands to std out

for PCAP_FILE in $UNSW_TRACES_DIR/*.pcap; do
    # skip non pcap files
    [ -e "$PCAP_FILE" ] || continue
    # make an output sub dir in the base output dir that is the filename minus extension
    OUTPUT_SUB_DIR=$(basename "$PCAP_FILE" .pcap)
    ./execute_layer3_unb_all_detection.sh $PCAP_FILE $SIGNATURES_BASE_DIR $OUTPUT_DIR/$OUTPUT_SUB_DIR
done