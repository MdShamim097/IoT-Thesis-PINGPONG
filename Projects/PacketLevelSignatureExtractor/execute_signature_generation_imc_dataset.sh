#!/bin/bash

#set -x # echo invoked commands to std out

# Base dir should point to the experimental_result folder which contains the subfolders:
# - 'smarthome' which contains the traces collected while other devices are idle
# - 'standalone' which contains signatures and the traces used to generate the signatures.

# TODO: This script has been used to extract signatures from the public dataset
# TODO: provided at https://moniotrlab.ccis.neu.edu/imc19/

# TODO: Please download the dataset yourself if you want to try this script.
# TODO: Please don't forget to preprocess the dataset using the instructions
# TODO:     in PingPong/evaluation-datasets/public-dataset/smarthome/README

# TODO: For a number of devices the CLUSTER_BOUNDS_MULTIPLIER should be as high as 0.9 or 0.99 due to
# TODO:     inconsistent network traces (see SignatureGenerator.java).
# TODO: For most cases, INCLUSION_WINDOW_MILLIS needs to be 30_000 (see TriggerTrafficExtractor.java).

BASE_DIR=$1
readonly BASE_DIR

OUTPUT_DIR=$2
readonly OUTPUT_DIR

SIGNATURES_BASE_DIR="$BASE_DIR/standalone"
readonly SIGNATURES_BASE_DIR

# ================================================== BLINK HUB PHOTO ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/blink-hub/blink-hub-photo/wlan/blink-hub-photo.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/blink-hub/blink-hub-photo/wlan/blink-hub-photo-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/blink-hub/blink-hub-photo/timestamps/blink-hub-photo.timestamps"
DEVICE_IP="192.168.10.207"
ON_SIGNATURE="$OUTPUT_DIR/blink-hub/blink-hub-photo/signatures/blink-hub-photo-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/blink-hub/blink-hub-photo/signatures/blink-hub-photo-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/blink-hub/blink-hub-photo/analyses/blink-hub-photo-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/blink-hub/blink-hub-photo/analyses/blink-hub-photo-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== BLINK HUB WATCH ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/blink-hub/blink-hub-watch/wlan/blink-hub-watch.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/blink-hub/blink-hub-watch/wlan/blink-hub-watch-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/blink-hub/blink-hub-watch/timestamps/blink-hub-watch.timestamps"
DEVICE_IP="192.168.10.207"
ON_SIGNATURE="$OUTPUT_DIR/blink-hub/blink-hub-watch/signatures/blink-hub-watch-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/blink-hub/blink-hub-watch/signatures/blink-hub-watch-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/blink-hub/blink-hub-watch/analyses/blink-hub-watch-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/blink-hub/blink-hub-watch/analyses/blink-hub-watch-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== BLINK CAMERA PHOTO ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-photo/wlan/blink-camera-photo.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/blink-camera/blink-camera-photo/wlan/blink-camera-photo-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-photo/timestamps/blink-camera-photo.timestamps"
DEVICE_IP="192.168.10.208"
ON_SIGNATURE="$OUTPUT_DIR/blink-camera/blink-camera-photo/signatures/blink-camera-photo-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/blink-camera/blink-camera-photo/signatures/blink-camera-photo-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/blink-camera/blink-camera-photo/analyses/blink-camera-photo-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/blink-camera/blink-camera-photo/analyses/blink-camera-photo-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== BLINK CAMERA WATCH ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-watch/wlan/blink-camera-watch.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/blink-camera/blink-camera-watch/wlan/blink-camera-watch-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-watch/timestamps/blink-camera-watch.timestamps"
DEVICE_IP="192.168.10.208"
ON_SIGNATURE="$OUTPUT_DIR/blink-camera/blink-camera-watch/signatures/blink-camera-watch-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/blink-camera/blink-camera-watch/signatures/blink-camera-watch-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/blink-camera/blink-camera-watch/analyses/blink-camera-watch-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/blink-camera/blink-camera-watch/analyses/blink-camera-watch-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== HUE BULB ON/OFF ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-onoff/wlan/hue-bulb-onoff.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/hue-bulb/hue-bulb-onoff/wlan/hue-bulb-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-onoff/timestamps/hue-bulb-onoff.timestamps"
DEVICE_IP="192.168.10.142"
ON_SIGNATURE="$OUTPUT_DIR/hue-bulb/hue-bulb-onoff/signatures/hue-bulb-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/hue-bulb/hue-bulb-onoff/signatures/hue-bulb-onoff-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/hue-bulb/hue-bulb-onoff/analyses/hue-bulb-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/hue-bulb/hue-bulb-onoff/analyses/hue-bulb-onoff-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= HUE BULB INTENSITY =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-intensity/wlan/hue-bulb-intensity.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/hue-bulb/hue-bulb-intensity/wlan/hue-bulb-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-intensity/timestamps/hue-bulb-intensity.timestamps"
DEVICE_IP="192.168.10.142"
ON_SIGNATURE="$OUTPUT_DIR/hue-bulb/hue-bulb-intensity/signatures/hue-bulb-intensity-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/hue-bulb/hue-bulb-intensity/signatures/hue-bulb-intensity-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/hue-bulb/hue-bulb-intensity/analyses/hue-bulb-intensity-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/hue-bulb/hue-bulb-intensity/analyses/hue-bulb-intensity-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =================================================== HUE BULB COLOR ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-color/wlan/hue-bulb-color.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/hue-bulb/hue-bulb-color/wlan/hue-bulb-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-color/timestamps/hue-bulb-color.timestamps"
DEVICE_IP="192.168.10.142"
ON_SIGNATURE="$OUTPUT_DIR/hue-bulb/hue-bulb-color/signatures/hue-bulb-color-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/hue-bulb/hue-bulb-color/signatures/hue-bulb-color-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/hue-bulb/hue-bulb-color/analyses/hue-bulb-color-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/hue-bulb/hue-bulb-color/analyses/hue-bulb-color-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="2"
DELETED_SEQUENCES_OFF="2"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== INSTEON HUB =====================================================
# TODO: SIGNATURE NOT FOUND HERE (BIG CLUSTERS)
INPUT_PCAP="$SIGNATURES_BASE_DIR/insteon-hub/wlan/insteon-hub.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/insteon-hub/wlan/insteon-hub-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/insteon-hub/timestamps/insteon-hub.timestamps"
DEVICE_IP="192.168.10.241"
ON_SIGNATURE="$OUTPUT_DIR/insteon-hub/signatures/insteon-hub-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/insteon-hub/signatures/insteon-hub-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/insteon-hub/analyses/insteon-hub-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/insteon-hub/analyses/insteon-hub-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ====================================================== IKETTLE =======================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/ikettle/wlan/ikettle.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/ikettle/wlan/ikettle-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/ikettle/timestamps/ikettle.timestamps"
DEVICE_IP="192.168.10.162"
ON_SIGNATURE="$OUTPUT_DIR/ikettle/signatures/ikettle-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/ikettle/signatures/ikettle-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/ikettle/analyses/ikettle-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/ikettle/analyses/ikettle-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: SIGNATURE NOT FOUND HERE (BIG CLUSTERS)
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= LIGHTIFY BULB ON/OFF ===============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/lightify-hub/lightify-hub-onoff/wlan/lightify-hub-onoff.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/lightify-hub/lightify-hub-onoff/wlan/lightify-hub-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/lightify-hub/lightify-hub-onoff/timestamps/lightify-hub-onoff.timestamps"
DEVICE_IP="192.168.10.149"
ON_SIGNATURE="$OUTPUT_DIR/lightify-hub/lightify-hub-onoff/signatures/lightify-hub-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/lightify-hub/lightify-hub-onoff/signatures/lightify-hub-onoff-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/lightify-hub/lightify-hub-onoff/analyses/lightify-hub-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/lightify-hub/lightify-hub-onoff/analyses/lightify-hub-onoff-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= LIGHTIFY BULB COLOR ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/lightify-hub/lightify-hub-color/wlan/lightify-hub-color.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/lightify-hub/lightify-hub-color/wlan/lightify-hub-color-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/lightify-hub/lightify-hub-color/timestamps/lightify-hub-color.timestamps"
DEVICE_IP="192.168.10.149"
ON_SIGNATURE="$OUTPUT_DIR/lightify-hub/lightify-hub-color/signatures/lightify-hub-color-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/lightify-hub/lightify-hub-color/signatures/lightify-hub-color-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/lightify-hub/lightify-hub-color/analyses/lightify-hub-color-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/lightify-hub/lightify-hub-color/analyses/lightify-hub-color-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== MAGICHOME STRIP ON/OFF ===============================================
# TODO: SIGNATURE NOT FOUND HERE (BIG CLUSTERS)
INPUT_PCAP="$SIGNATURES_BASE_DIR/magichome-strip/magichome-strip-onoff/wlan/magichome-strip-onoff.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/magichome-strip/magichome-strip-onoff/wlan/magichome-strip-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/magichome-strip/magichome-strip-onoff/timestamps/magichome-strip-onoff.timestamps"
DEVICE_IP="192.168.10.186"
ON_SIGNATURE="$OUTPUT_DIR/magichome-strip/magichome-strip-onoff/signatures/magichome-strip-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/magichome-strip/magichome-strip-onoff/signatures/magichome-strip-onoff-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/magichome-strip/magichome-strip-onoff/analyses/magichome-strip-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/magichome-strip/magichome-strip-onoff/analyses/magichome-strip-onoff-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== NEST THERMOSTAT ON/OFF ===============================================
# TODO: WE EXTRACTED DIFFERENT FEATURES FOR NEST
INPUT_PCAP="$SIGNATURES_BASE_DIR/nest-thermostat/nest-thermostat-onoff/wlan/nest-thermostat-onoff.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/nest-thermostat/nest-thermostat-onoff/wlan/nest-thermostat-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/nest-thermostat/nest-thermostat-onoff/timestamps/nest-thermostat-onoff.timestamps"
DEVICE_IP="192.168.10.246"
ON_SIGNATURE="$OUTPUT_DIR/nest-thermostat/nest-thermostat-onoff/signatures/nest-thermostat-onoff-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/nest-thermostat/nest-thermostat-onoff/signatures/nest-thermostat-onoff-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/nest-thermostat/nest-thermostat-onoff/analyses/nest-thermostat-onoff-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/nest-thermostat/nest-thermostat-onoff/analyses/nest-thermostat-onoff-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== SENGLED BULB ON/OFF ==================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/sengled-hub/sengled-hub-onoff/wlan/sengled-hub-onoff.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/sengled-hub/sengled-hub-onoff/wlan/sengled-hub-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/sengled-hub/sengled-hub-onoff/timestamps/sengled-hub-onoff.timestamps"
DEVICE_IP="192.168.10.202"
ON_SIGNATURE="$OUTPUT_DIR/sengled-hub/sengled-hub-onoff/signatures/sengled-hub-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/sengled-hub/sengled-hub-onoff/signatures/sengled-hub-onoff-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/sengled-hub/sengled-hub-onoff/analyses/sengled-hub-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/sengled-hub/sengled-hub-onoff/analyses/sengled-hub-onoff-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="0"
DELETED_SEQUENCES_OFF="3"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== SENGLED BULB INTENSITY ===============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/sengled-hub/sengled-hub-intensity/wlan/sengled-hub-intensity.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/sengled-hub/sengled-hub-intensity/wlan/sengled-hub-intensity-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/sengled-hub/sengled-hub-intensity/timestamps/sengled-hub-intensity.timestamps"
DEVICE_IP="192.168.10.202"
ON_SIGNATURE="$OUTPUT_DIR/sengled-hub/sengled-hub-intensity/signatures/sengled-hub-intensity-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/sengled-hub/sengled-hub-intensity/signatures/sengled-hub-intensity-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/sengled-hub/sengled-hub-intensity/analyses/sengled-hub-intensity-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/sengled-hub/sengled-hub-intensity/analyses/sengled-hub-intensity-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= SENGLED BULB COLOR =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/sengled-hub/sengled-hub-color/wlan/sengled-hub-color.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/sengled-hub/sengled-hub-color/wlan/sengled-hub-color-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/sengled-hub/sengled-hub-color/timestamps/sengled-hub-color.timestamps"
DEVICE_IP="192.168.10.202"
ON_SIGNATURE="$OUTPUT_DIR/sengled-hub/sengled-hub-color/signatures/sengled-hub-color-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/sengled-hub/sengled-hub-color/signatures/sengled-hub-color-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/sengled-hub/sengled-hub-color/analyses/sengled-hub-color-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/sengled-hub/sengled-hub-color/analyses/sengled-hub-color-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="0,0,2"
DELETED_SEQUENCES_OFF="0,0,0,2"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= TP LINK BULB ON/OFF ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/wlan/tplink-bulb-onoff.wlan.pcap"

# It seems that ON and OFF clusters are swapped
OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/wlan/tplink-bulb-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff.timestamps"
DEVICE_IP="192.168.10.146"
ON_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/signatures/tplink-bulb-onoff-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/signatures/tplink-bulb-onoff-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/analyses/tplink-bulb-onoff-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/analyses/tplink-bulb-onoff-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="3,0,1"
DELETED_SEQUENCES_OFF="4,1,1,1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= TP LINK BULB COLOR =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/wlan/tplink-bulb-color.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/wlan/tplink-bulb-color-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/timestamps/tplink-bulb-color.timestamps"
DEVICE_IP="192.168.10.146"
ON_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/signatures/tplink-bulb-color-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/signatures/tplink-bulb-color-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/analyses/tplink-bulb-color-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/analyses/tplink-bulb-color-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="0"
DELETED_SEQUENCES_OFF="0"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== TP LINK BULB INTENSITY ===============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/wlan/tplink-bulb-intensity.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/wlan/tplink-bulb-intensity-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/timestamps/tplink-bulb-intensity.timestamps"
DEVICE_IP="192.168.10.146"
ON_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/signatures/tplink-bulb-intensity-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/signatures/tplink-bulb-intensity-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/analyses/tplink-bulb-intensity-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/analyses/tplink-bulb-intensity-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="0"
DELETED_SEQUENCES_OFF="0"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== TP-LINK PLUG ====================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-plug/wlan/tplink-plug.wlan.pcap"

# It seems that ON and OFF clusters are swapped (ON should have been odd and OFF should have been even numbers).
OUTPUT_PCAP="$OUTPUT_DIR/tplink-plug/wlan/tplink-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-plug/timestamps/tplink-plug.timestamps"
DEVICE_IP="192.168.10.247"
ON_SIGNATURE="$OUTPUT_DIR/tplink-plug/signatures/tplink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-plug/signatures/tplink-plug-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-plug/analyses/tplink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-plug/analyses/tplink-plug-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="2"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== WEMO INSIGHT PLUG =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/wemo-insight-plug/wlan/wemo-insight-plug.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/wemo-insight-plug/wlan/wemo-insight-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wemo-insight-plug/timestamps/wemo-insight-plug.timestamps"
DEVICE_IP="192.168.10.143"
ON_SIGNATURE="$OUTPUT_DIR/wemo-insight-plug/signatures/wemo-insight-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/wemo-insight-plug/signatures/wemo-insight-plug-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/wemo-insight-plug/analyses/wemo-insight-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/wemo-insight-plug/analyses/wemo-insight-plug-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="0"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# TODO: MORE SIGNATURE EXTRACTIONS
# ================================================ ALLURE SPEAKER ON/OFF ===============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/allure-speaker/allure-speaker-audio-onoff/wlan/allure-speaker-audio-onoff.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/allure-speaker/allure-speaker-audio-onoff/wlan/allure-speaker-audio-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/allure-speaker/allure-speaker-audio-onoff/timestamps/allure-speaker-audio-onoff.timestamps"
DEVICE_IP="192.168.20.132"
ON_SIGNATURE="$OUTPUT_DIR/allure-speaker/allure-speaker-audio-onoff/signatures/allure-speaker-audio-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/allure-speaker/allure-speaker-audio-onoff/signatures/allure-speaker-audio-onoff-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/allure-speaker/allure-speaker-audio-onoff/analyses/allure-speaker-audio-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/allure-speaker/allure-speaker-audio-onoff/analyses/allure-speaker-audio-onoff-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="2,0"
DELETED_SEQUENCES_OFF="2,0"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.9 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================ ALLURE SPEAKER VOICE ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/allure-speaker/allure-speaker-voice/wlan/allure-speaker-voice.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/allure-speaker/allure-speaker-voice/wlan/allure-speaker-voice-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/allure-speaker/allure-speaker-voice/timestamps/allure-speaker-voice.timestamps"
DEVICE_IP="192.168.20.132"
ON_SIGNATURE="$OUTPUT_DIR/allure-speaker/allure-speaker-voice/signatures/allure-speaker-voice-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/allure-speaker/allure-speaker-voice/signatures/allure-speaker-voice-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/allure-speaker/allure-speaker-voice/analyses/allure-speaker-voice-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/allure-speaker/allure-speaker-voice/analyses/allure-speaker-voice-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: NO RELEVANT CLUSTERS
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================ ALLURE SPEAKER VOLUME ===============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/allure-speaker/allure-speaker-volume/wlan/allure-speaker-volume.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/allure-speaker/allure-speaker-volume/wlan/allure-speaker-volume-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/allure-speaker/allure-speaker-volume/timestamps/allure-speaker-volume.timestamps"
DEVICE_IP="192.168.20.132"
ON_SIGNATURE="$OUTPUT_DIR/allure-speaker/allure-speaker-volume/signatures/allure-speaker-volume-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/allure-speaker/allure-speaker-volume/signatures/allure-speaker-volume-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/allure-speaker/allure-speaker-volume/analyses/allure-speaker-volume-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/allure-speaker/allure-speaker-volume/analyses/allure-speaker-volume-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================ AMAZON CAMERA WATCH =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/amazon-camera/amazon-camera-watch/wlan/amazon-camera-watch.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/amazon-camera/amazon-camera-watch/wlan/amazon-camera-watch-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/amazon-camera/amazon-camera-watch/timestamps/amazon-camera-watch.timestamps"
DEVICE_IP="192.168.10.203"
ON_SIGNATURE="$OUTPUT_DIR/amazon-camera/amazon-camera-watch/signatures/amazon-camera-watch-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/amazon-camera/amazon-camera-watch/signatures/amazon-camera-watch-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/amazon-camera/amazon-camera-watch/analyses/amazon-camera-watch-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/amazon-camera/amazon-camera-watch/analyses/amazon-camera-watch-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="2,1"
DELETED_SEQUENCES_OFF="2,0"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================ BOSIWO CAMERA RECORDING =============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/bosiwo-camera/bosiwo-camera-recording/wlan/bosiwo-camera-recording.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/bosiwo-camera/bosiwo-camera-recording/wlan/bosiwo-camera-recording-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/bosiwo-camera/bosiwo-camera-recording/timestamps/bosiwo-camera-recording.timestamps"
DEVICE_IP="192.168.20.115"
ON_SIGNATURE="$OUTPUT_DIR/bosiwo-camera/bosiwo-camera-recording/signatures/bosiwo-camera-recording-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/bosiwo-camera/bosiwo-camera-recording/signatures/bosiwo-camera-recording-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/bosiwo-camera/bosiwo-camera-recording/analyses/bosiwo-camera-recording-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/bosiwo-camera/bosiwo-camera-recording/analyses/bosiwo-camera-recording-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: UDP based device
# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================ BOSIWO CAMERA WATCH =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/bosiwo-camera/bosiwo-camera-watch/wlan/bosiwo-camera-watch.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/bosiwo-camera/bosiwo-camera-watch/wlan/bosiwo-camera-watch-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/bosiwo-camera/bosiwo-camera-watch/timestamps/bosiwo-camera-watch.timestamps"
DEVICE_IP="192.168.20.115"
ON_SIGNATURE="$OUTPUT_DIR/bosiwo-camera/bosiwo-camera-watch/signatures/bosiwo-camera-watch-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/bosiwo-camera/bosiwo-camera-watch/signatures/bosiwo-camera-watch-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/bosiwo-camera/bosiwo-camera-watch/analyses/bosiwo-camera-watch-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/bosiwo-camera/bosiwo-camera-watch/analyses/bosiwo-camera-watch-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: UDP based device
# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== BEHMOR BREWER =====================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/brewer/wlan/brewer.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/brewer/wlan/brewer-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/brewer/timestamps/brewer.timestamps"
DEVICE_IP="192.168.10.227"
ON_SIGNATURE="$OUTPUT_DIR/brewer/signatures/brewer-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/brewer/signatures/brewer-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/brewer/analyses/brewer-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/brewer/analyses/brewer-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Big clusters (did not extract anything)---they seem to have their proprietary protocol over TCP
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================ CHARGER CAMERA WATCH ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/charger-camera/charger-camera-watch/wlan/charger-camera-watch.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/charger-camera/charger-camera-watch/wlan/charger-camera-watch-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/charger-camera/charger-camera-watch/timestamps/charger-camera-watch.timestamps"
DEVICE_IP="192.168.20.158"
ON_SIGNATURE="$OUTPUT_DIR/charger-camera/charger-camera-watch/signatures/charger-camera-watch-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/charger-camera/charger-camera-watch/signatures/charger-camera-watch-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/charger-camera/charger-camera-watch/analyses/charger-camera-watch-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/charger-camera/charger-camera-watch/analyses/charger-camera-watch-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: UDP based device
# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== ECHO DOT AUDIO ON/OFF =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/echodot/echodot-audio-onoff/wlan/echodot-audio-onoff.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/echodot/echodot-audio-onoff/wlan/echodot-audio-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/echodot/echodot-audio-onoff/timestamps/echodot-audio-onoff.timestamps"
DEVICE_IP="192.168.20.112"
ON_SIGNATURE="$OUTPUT_DIR/echodot/echodot-audio-onoff/signatures/echodot-audio-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/echodot/echodot-audio-onoff/signatures/echodot-audio-onoff-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/echodot/echodot-audio-onoff/analyses/echodot-audio-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/echodot/echodot-audio-onoff/analyses/echodot-audio-onoff-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: NO SIGNATURE HERE! BIG CLUSTERS!
# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= ECHO DOT VOICE =====================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/echodot/echodot-voice/wlan/echodot-voice.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/echodot/echodot-voice/wlan/echodot-voice-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/echodot/echodot-voice/timestamps/echodot-voice.timestamps"
DEVICE_IP="192.168.10.104"
ON_SIGNATURE="$OUTPUT_DIR/echodot/echodot-voice/signatures/echodot-voice-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/echodot/echodot-voice/signatures/echodot-voice-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/echodot/echodot-voice/analyses/echodot-voice-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/echodot/echodot-voice/analyses/echodot-voice-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="0"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.1 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= ECHO DOT VOLUME ====================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/echodot/echodot-volume/wlan/echodot-volume.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/echodot/echodot-volume/wlan/echodot-volume-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/echodot/echodot-volume/timestamps/echodot-volume.timestamps"
DEVICE_IP="192.168.10.104"
ON_SIGNATURE="$OUTPUT_DIR/echodot/echodot-volume/signatures/echodot-volume-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/echodot/echodot-volume/signatures/echodot-volume-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/echodot/echodot-volume/analyses/echodot-volume-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/echodot/echodot-volume/analyses/echodot-volume-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== ECHO PLUS AUDIO ON/OFF ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/echoplus/echoplus-audio-onoff/wlan/echoplus-audio-onoff.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/echoplus/echoplus-audio-onoff/wlan/echoplus-audio-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/echoplus/echoplus-audio-onoff/timestamps/echoplus-audio-onoff.timestamps"
DEVICE_IP="192.168.10.201"
ON_SIGNATURE="$OUTPUT_DIR/echoplus/echoplus-audio-onoff/signatures/echoplus-audio-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/echoplus/echoplus-audio-onoff/signatures/echoplus-audio-onoff-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/echoplus/echoplus-audio-onoff/analyses/echoplus-audio-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/echoplus/echoplus-audio-onoff/analyses/echoplus-audio-onoff-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.1 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= ECHO PLUS COLOR ====================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/echoplus/echoplus-color/wlan/echoplus-color.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/echoplus/echoplus-color/wlan/echoplus-color-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/echoplus/echoplus-color/timestamps/echoplus-color.timestamps"
DEVICE_IP="192.168.10.201"
ON_SIGNATURE="$OUTPUT_DIR/echoplus/echoplus-color/signatures/echoplus-color-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/echoplus/echoplus-color/signatures/echoplus-color-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/echoplus/echoplus-color/analyses/echoplus-color-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/echoplus/echoplus-color/analyses/echoplus-color-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.1 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== ECHO PLUS INTENSITY ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/echoplus/echoplus-intensity/wlan/echoplus-intensity.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/echoplus/echoplus-intensity/wlan/echoplus-intensity-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/echoplus/echoplus-intensity/timestamps/echoplus-intensity.timestamps"
DEVICE_IP="192.168.10.201"
ON_SIGNATURE="$OUTPUT_DIR/echoplus/echoplus-intensity/signatures/echoplus-intensity-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/echoplus/echoplus-intensity/signatures/echoplus-intensity-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/echoplus/echoplus-intensity/analyses/echoplus-intensity-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/echoplus/echoplus-intensity/analyses/echoplus-intensity-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.1 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= ECHO PLUS VOICE ====================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/echoplus/echoplus-voice/wlan/echoplus-voice.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/echoplus/echoplus-voice/wlan/echoplus-voice-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/echoplus/echoplus-voice/timestamps/echoplus-voice.timestamps"
DEVICE_IP="192.168.10.201"
ON_SIGNATURE="$OUTPUT_DIR/echoplus/echoplus-voice/signatures/echoplus-voice-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/echoplus/echoplus-voice/signatures/echoplus-voice-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/echoplus/echoplus-voice/analyses/echoplus-voice-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/echoplus/echoplus-voice/analyses/echoplus-voice-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.1 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= ECHO PLUS VOLUME ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/echoplus/echoplus-volume/wlan/echoplus-volume.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/echoplus/echoplus-volume/wlan/echoplus-volume-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/echoplus/echoplus-volume/timestamps/echoplus-volume.timestamps"
DEVICE_IP="192.168.10.201"
ON_SIGNATURE="$OUTPUT_DIR/echoplus/echoplus-volume/signatures/echoplus-volume-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/echoplus/echoplus-volume/signatures/echoplus-volume-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/echoplus/echoplus-volume/analyses/echoplus-volume-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/echoplus/echoplus-volume/analyses/echoplus-volume-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.1 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== ECHO SPOT AUDIO ON/OFF ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/echospot/echospot-audio-onoff/wlan/echospot-audio-onoff.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/echospot/echospot-audio-onoff/wlan/echospot-audio-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/echospot/echospot-audio-onoff/timestamps/echospot-audio-onoff.timestamps"
DEVICE_IP="192.168.10.147"
ON_SIGNATURE="$OUTPUT_DIR/echospot/echospot-audio-onoff/signatures/echospot-audio-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/echospot/echospot-audio-onoff/signatures/echospot-audio-onoff-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/echospot/echospot-audio-onoff/analyses/echospot-audio-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/echospot/echospot-audio-onoff/analyses/echospot-audio-onoff-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.1 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= ECHO SPOT VOICE ====================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/echospot/echospot-voice/wlan/echospot-voice.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/echospot/echospot-voice/wlan/echospot-voice-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/echospot/echospot-voice/timestamps/echospot-voice.timestamps"
DEVICE_IP="192.168.10.147"
ON_SIGNATURE="$OUTPUT_DIR/echospot/echospot-voice/signatures/echospot-voice-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/echospot/echospot-voice/signatures/echospot-voice-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/echospot/echospot-voice/analyses/echospot-voice-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/echospot/echospot-voice/analyses/echospot-voice-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="2"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.1 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= ECHO SPOT VOLUME ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/echospot/echospot-volume/wlan/echospot-volume.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/echospot/echospot-volume/wlan/echospot-volume-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/echospot/echospot-volume/timestamps/echospot-volume.timestamps"
DEVICE_IP="192.168.10.147"
ON_SIGNATURE="$OUTPUT_DIR/echospot/echospot-volume/signatures/echospot-volume-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/echospot/echospot-volume/signatures/echospot-volume-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/echospot/echospot-volume/analyses/echospot-volume-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/echospot/echospot-volume/analyses/echospot-volume-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.1 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =================================================== FIRE-TV MENU =====================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/firetv/firetv-menu/wlan/firetv-menu.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/firetv/firetv-menu/wlan/firetv-menu-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/firetv/firetv-menu/timestamps/firetv-menu.timestamps"
DEVICE_IP="192.168.10.158"
ON_SIGNATURE="$OUTPUT_DIR/firetv/firetv-menu/signatures/firetv-menu-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/firetv/firetv-menu/signatures/firetv-menu-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/firetv/firetv-menu/analyses/firetv-menu-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/firetv/firetv-menu/analyses/firetv-menu-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="0,1"
DELETED_SEQUENCES_OFF="1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.3 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== FLEX BULB COLOR ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/flex-bulb/flex-bulb-color/wlan/flex-bulb-color.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/flex-bulb/flex-bulb-color/wlan/flex-bulb-color-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/flex-bulb/flex-bulb-color/timestamps/flex-bulb-color.timestamps"
DEVICE_IP="192.168.10.132"
ON_SIGNATURE="$OUTPUT_DIR/flex-bulb/flex-bulb-color/signatures/flex-bulb-color-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/flex-bulb/flex-bulb-color/signatures/flex-bulb-color-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/flex-bulb/flex-bulb-color/analyses/flex-bulb-color-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/flex-bulb/flex-bulb-color/analyses/flex-bulb-color-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="0"
DELETED_SEQUENCES_OFF="1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================ FLEX BULB INTENSITY =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/flex-bulb/flex-bulb-intensity/wlan/flex-bulb-intensity.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/flex-bulb/flex-bulb-intensity/wlan/flex-bulb-intensity-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/flex-bulb/flex-bulb-intensity/timestamps/flex-bulb-intensity.timestamps"
DEVICE_IP="192.168.10.132"
ON_SIGNATURE="$OUTPUT_DIR/flex-bulb/flex-bulb-intensity/signatures/flex-bulb-intensity-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/flex-bulb/flex-bulb-intensity/signatures/flex-bulb-intensity-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/flex-bulb/flex-bulb-intensity/analyses/flex-bulb-intensity-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/flex-bulb/flex-bulb-intensity/analyses/flex-bulb-intensity-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="0"
DELETED_SEQUENCES_OFF="0,1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== FLEX BULB ON/OFF ==================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/flex-bulb/flex-bulb-onoff/wlan/flex-bulb-onoff.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/flex-bulb/flex-bulb-onoff/wlan/flex-bulb-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/flex-bulb/flex-bulb-onoff/timestamps/flex-bulb-onoff.timestamps"
DEVICE_IP="192.168.10.132"
ON_SIGNATURE="$OUTPUT_DIR/flex-bulb/flex-bulb-onoff/signatures/flex-bulb-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/flex-bulb/flex-bulb-onoff/signatures/flex-bulb-onoff-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/flex-bulb/flex-bulb-onoff/analyses/flex-bulb-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/flex-bulb/flex-bulb-onoff/analyses/flex-bulb-onoff-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="0"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= GOOGLE HOME VOICE ==================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/google-home/google-home-voice/wlan/google-home-voice.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/google-home/google-home-voice/wlan/google-home-voice-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/google-home/google-home-voice/timestamps/google-home-voice.timestamps"
DEVICE_IP="192.168.20.114"
ON_SIGNATURE="$OUTPUT_DIR/google-home/google-home-voice/signatures/google-home-voice-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/google-home/google-home-voice/signatures/google-home-voice-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/google-home/google-home-voice/analyses/google-home-voice-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/google-home/google-home-voice/analyses/google-home-voice-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.3 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================ GOOGLE HOME VOLUME ==================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/google-home/google-home-volume/wlan/google-home-volume.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/google-home/google-home-volume/wlan/google-home-volume-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/google-home/google-home-volume/timestamps/google-home-volume.timestamps"
DEVICE_IP="192.168.20.114"
ON_SIGNATURE="$OUTPUT_DIR/google-home/google-home-volume/signatures/google-home-volume-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/google-home/google-home-volume/signatures/google-home-volume-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/google-home/google-home-volume/analyses/google-home-volume-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/google-home/google-home-volume/analyses/google-home-volume-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="3,2"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== GOOGLE HOME MINI VOICE ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/google-home-mini/google-home-mini-voice/wlan/google-home-mini-voice.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/google-home-mini/google-home-mini-voice/wlan/google-home-mini-voice-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/google-home-mini/google-home-mini-voice/timestamps/google-home-mini-voice.timestamps"
DEVICE_IP="192.168.10.225"
ON_SIGNATURE="$OUTPUT_DIR/google-home-mini/google-home-mini-voice/signatures/google-home-mini-voice-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/google-home-mini/google-home-mini-voice/signatures/google-home-mini-voice-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/google-home-mini/google-home-mini-voice/analyses/google-home-mini-voice-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/google-home-mini/google-home-mini-voice/analyses/google-home-mini-voice-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="0,1"
DELETED_SEQUENCES_OFF="1,0,1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.4 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== GOOGLE HOME MINI VOLUME ===============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/google-home-mini/google-home-mini-volume/wlan/google-home-mini-volume.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/google-home-mini/google-home-mini-volume/wlan/google-home-mini-volume-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/google-home-mini/google-home-mini-volume/timestamps/google-home-mini-volume.timestamps"
DEVICE_IP="192.168.10.225"
ON_SIGNATURE="$OUTPUT_DIR/google-home-mini/google-home-mini-volume/signatures/google-home-mini-volume-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/google-home-mini/google-home-mini-volume/signatures/google-home-mini-volume-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/google-home-mini/google-home-mini-volume/analyses/google-home-mini-volume-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/google-home-mini/google-home-mini-volume/analyses/google-home-mini-volume-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="0,0"
DELETED_SEQUENCES_OFF="0,1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.4 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================ HONEYWELL THERMOSTAT ON/OFF =============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/honeywell-thermostat/honeywell-thermostat-onoff/wlan/honeywell-thermostat-onoff.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/honeywell-thermostat/honeywell-thermostat-onoff/wlan/honeywell-thermostat-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/honeywell-thermostat/honeywell-thermostat-onoff/timestamps/honeywell-thermostat-onoff.timestamps"
DEVICE_IP="192.168.20.103"
ON_SIGNATURE="$OUTPUT_DIR/honeywell-thermostat/honeywell-thermostat-onoff/signatures/honeywell-thermostat-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/honeywell-thermostat/honeywell-thermostat-onoff/signatures/honeywell-thermostat-onoff-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/honeywell-thermostat/honeywell-thermostat-onoff/analyses/honeywell-thermostat-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/honeywell-thermostat/honeywell-thermostat-onoff/analyses/honeywell-thermostat-onoff-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.5 and INCLUSION_WINDOW_MILLIS = 30_000
# TODO: Also the datapoints could only be 4
# TODO: 05/04/2019 12:13:20 PM #05/04/2019 12:14:03 PM #05/04/2019 12:31:39 PM #05/04/2019 12:32:21 PM
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================= HONEYWELL THERMOSTAT SET ===============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/honeywell-thermostat/honeywell-thermostat-set/wlan/honeywell-thermostat-set.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/honeywell-thermostat/honeywell-thermostat-set/wlan/honeywell-thermostat-set-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/honeywell-thermostat/honeywell-thermostat-set/timestamps/honeywell-thermostat-set.timestamps"
DEVICE_IP="192.168.20.103"
ON_SIGNATURE="$OUTPUT_DIR/honeywell-thermostat/honeywell-thermostat-set/signatures/honeywell-thermostat-set-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/honeywell-thermostat/honeywell-thermostat-set/signatures/honeywell-thermostat-set-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/honeywell-thermostat/honeywell-thermostat-set/analyses/honeywell-thermostat-set-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/honeywell-thermostat/honeywell-thermostat-set/analyses/honeywell-thermostat-set-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Clusters are small, presumably due to broken PCAP files (their recording seems to be inconsistent and noisy)
# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.9 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== INVOKE SPEAKER VOICE ==================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/invoke-speaker/invoke-speaker-voice/wlan/invoke-speaker-voice.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/invoke-speaker/invoke-speaker-voice/wlan/invoke-speaker-voice-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/invoke-speaker/invoke-speaker-voice/timestamps/invoke-speaker-voice.timestamps"
DEVICE_IP="192.168.10.213"
ON_SIGNATURE="$OUTPUT_DIR/invoke-speaker/invoke-speaker-voice/signatures/invoke-speaker-voice-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/invoke-speaker/invoke-speaker-voice/signatures/invoke-speaker-voice-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/invoke-speaker/invoke-speaker-voice/analyses/invoke-speaker-voice-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/invoke-speaker/invoke-speaker-voice/analyses/invoke-speaker-voice-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="2"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== INVOKE SPEAKER VOLUME =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/invoke-speaker/invoke-speaker-volume/wlan/invoke-speaker-volume.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/invoke-speaker/invoke-speaker-volume/wlan/invoke-speaker-volume-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/invoke-speaker/invoke-speaker-volume/timestamps/invoke-speaker-volume.timestamps"
DEVICE_IP="192.168.10.213"
ON_SIGNATURE="$OUTPUT_DIR/invoke-speaker/invoke-speaker-volume/signatures/invoke-speaker-volume-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/invoke-speaker/invoke-speaker-volume/signatures/invoke-speaker-volume-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/invoke-speaker/invoke-speaker-volume/analyses/invoke-speaker-volume-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/invoke-speaker/invoke-speaker-volume/analyses/invoke-speaker-volume-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="1,0,0"
DELETED_SEQUENCES_OFF="0,0,2"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== LEFUN CAMERA PHOTO ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/lefun-camera/lefun-camera-photo/wlan/lefun-camera-photo.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/lefun-camera/lefun-camera-photo/wlan/lefun-camera-photo-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/lefun-camera/lefun-camera-photo/timestamps/lefun-camera-photo.timestamps"
DEVICE_IP="192.168.10.210"
ON_SIGNATURE="$OUTPUT_DIR/lefun-camera/lefun-camera-photo/signatures/lefun-camera-photo-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/lefun-camera/lefun-camera-photo/signatures/lefun-camera-photo-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/lefun-camera/lefun-camera-photo/analyses/lefun-camera-photo-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/lefun-camera/lefun-camera-photo/analyses/lefun-camera-photo-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.3 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================= LEFUN CAMERA RECORDING =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/lefun-camera/lefun-camera-recording/wlan/lefun-camera-recording.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/lefun-camera/lefun-camera-recording/wlan/lefun-camera-recording-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/lefun-camera/lefun-camera-recording/timestamps/lefun-camera-recording.timestamps"
DEVICE_IP="192.168.10.210"
ON_SIGNATURE="$OUTPUT_DIR/lefun-camera/lefun-camera-recording/signatures/lefun-camera-recording-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/lefun-camera/lefun-camera-recording/signatures/lefun-camera-recording-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/lefun-camera/lefun-camera-recording/analyses/lefun-camera-recording-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/lefun-camera/lefun-camera-recording/analyses/lefun-camera-recording-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.3 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== LEFUN CAMERA WATCH ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/lefun-camera/lefun-camera-watch/wlan/lefun-camera-watch.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/lefun-camera/lefun-camera-watch/wlan/lefun-camera-watch-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/lefun-camera/lefun-camera-watch/timestamps/lefun-camera-watch.timestamps"
DEVICE_IP="192.168.10.210"
ON_SIGNATURE="$OUTPUT_DIR/lefun-camera/lefun-camera-watch/signatures/lefun-camera-watch-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/lefun-camera/lefun-camera-watch/signatures/lefun-camera-watch-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/lefun-camera/lefun-camera-watch/analyses/lefun-camera-watch-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/lefun-camera/lefun-camera-watch/analyses/lefun-camera-watch-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.3 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =================================================== LG-TV MENU =====================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/lgtv-wired/lgtv-wired-menu/wlan/lgtv-wired-menu.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/lgtv-wired/lgtv-wired-menu/wlan/lgtv-wired-menu-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/lgtv-wired/lgtv-wired-menu/timestamps/lgtv-wired-menu.timestamps"
DEVICE_IP="192.168.10.120"
ON_SIGNATURE="$OUTPUT_DIR/lgtv-wired/lgtv-wired-menu/signatures/lgtv-wired-menu-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/lgtv-wired/lgtv-wired-menu/signatures/lgtv-wired-menu-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/lgtv-wired/lgtv-wired-menu/analyses/lgtv-wired-menu-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/lgtv-wired/lgtv-wired-menu/analyses/lgtv-wired-menu-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.1 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== LUOHE CAMERA PHOTO ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/luohe-camera/luohe-camera-photo/wlan/luohe-camera-photo.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/luohe-camera/luohe-camera-photo/wlan/luohe-camera-photo-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/luohe-camera/luohe-camera-photo/timestamps/luohe-camera-photo.timestamps"
DEVICE_IP="192.168.10.209"
ON_SIGNATURE="$OUTPUT_DIR/luohe-camera/luohe-camera-photo/signatures/luohe-camera-photo-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/luohe-camera/luohe-camera-photo/signatures/luohe-camera-photo-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/luohe-camera/luohe-camera-photo/analyses/luohe-camera-photo-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/luohe-camera/luohe-camera-photo/analyses/luohe-camera-photo-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================= LUOHE CAMERA RECORDING =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/luohe-camera/luohe-camera-recording/wlan/luohe-camera-recording.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/luohe-camera/luohe-camera-recording/wlan/luohe-camera-recording-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/luohe-camera/luohe-camera-recording/timestamps/luohe-camera-recording.timestamps"
DEVICE_IP="192.168.10.209"
ON_SIGNATURE="$OUTPUT_DIR/luohe-camera/luohe-camera-recording/signatures/luohe-camera-recording-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/luohe-camera/luohe-camera-recording/signatures/luohe-camera-recording-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/luohe-camera/luohe-camera-recording/analyses/luohe-camera-recording-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/luohe-camera/luohe-camera-recording/analyses/luohe-camera-recording-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== LUOHE CAMERA WATCH ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/luohe-camera/luohe-camera-watch/wlan/luohe-camera-watch.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/luohe-camera/luohe-camera-watch/wlan/luohe-camera-watch-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/luohe-camera/luohe-camera-watch/timestamps/luohe-camera-watch.timestamps"
DEVICE_IP="192.168.10.209"
ON_SIGNATURE="$OUTPUT_DIR/luohe-camera/luohe-camera-watch/signatures/luohe-camera-watch-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/luohe-camera/luohe-camera-watch/signatures/luohe-camera-watch-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/luohe-camera/luohe-camera-watch/analyses/luohe-camera-watch-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/luohe-camera/luohe-camera-watch/analyses/luohe-camera-watch-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================= MICROSEVEN CAMERA WATCH ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/microseven-camera/microseven-camera-watch/wlan/microseven-camera-watch.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/microseven-camera/microseven-camera-watch/wlan/microseven-camera-watch-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/microseven-camera/microseven-camera-watch/timestamps/microseven-camera-watch.timestamps"
DEVICE_IP="192.168.10.117"
ON_SIGNATURE="$OUTPUT_DIR/microseven-camera/microseven-camera-watch/signatures/microseven-camera-watch-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/microseven-camera/microseven-camera-watch/signatures/microseven-camera-watch-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/microseven-camera/microseven-camera-watch/analyses/microseven-camera-watch-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/microseven-camera/microseven-camera-watch/analyses/microseven-camera-watch-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="0,0"
DELETED_SEQUENCES_OFF="2,0"

# TODO: Made the dataset smaller (just 10 events)
# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.5 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ========================================= NETATMO WEATHER STATION GRAPHS =============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/netatmo-weather-station/netatmo-weather-station-graphs/wlan/netatmo-weather-station-graphs.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/netatmo-weather-station/netatmo-weather-station-graphs/wlan/netatmo-weather-station-graphs-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/netatmo-weather-station/netatmo-weather-station-graphs/timestamps/netatmo-weather-station-graphs.timestamps"
DEVICE_IP="192.168.20.104"
ON_SIGNATURE="$OUTPUT_DIR/netatmo-weather-station/netatmo-weather-station-graphs/signatures/netatmo-weather-station-graphs-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/netatmo-weather-station/netatmo-weather-station-graphs/signatures/netatmo-weather-station-graphs-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/netatmo-weather-station/netatmo-weather-station-graphs/analyses/netatmo-weather-station-graphs-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/netatmo-weather-station/netatmo-weather-station-graphs/analyses/netatmo-weather-station-graphs-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: This contains empty PCAP files
# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =========================================== NETATMO WEATHER STATION SET ==============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/netatmo-weather-station/netatmo-weather-station-set/wlan/netatmo-weather-station-set.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/netatmo-weather-station/netatmo-weather-station-set/wlan/netatmo-weather-station-set-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/netatmo-weather-station/netatmo-weather-station-set/timestamps/netatmo-weather-station-set.timestamps"
DEVICE_IP="192.168.20.104"
ON_SIGNATURE="$OUTPUT_DIR/netatmo-weather-station/netatmo-weather-station-set/signatures/netatmo-weather-station-set-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/netatmo-weather-station/netatmo-weather-station-set/signatures/netatmo-weather-station-set-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/netatmo-weather-station/netatmo-weather-station-set/analyses/netatmo-weather-station-set-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/netatmo-weather-station/netatmo-weather-station-set/analyses/netatmo-weather-station-set-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: This contains empty PCAP files
# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= ROKU-TV REMOTE =====================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/roku-tv/roku-tv-remote/wlan/roku-tv-remote.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/roku-tv/roku-tv-remote/wlan/roku-tv-remote-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/roku-tv/roku-tv-remote/timestamps/roku-tv-remote.timestamps"
DEVICE_IP="192.168.10.239"
ON_SIGNATURE="$OUTPUT_DIR/roku-tv/roku-tv-remote/signatures/roku-tv-remote-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/roku-tv/roku-tv-remote/signatures/roku-tv-remote-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/roku-tv/roku-tv-remote/analyses/roku-tv-remote-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/roku-tv/roku-tv-remote/analyses/roku-tv-remote-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="3"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.1 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== SAMSUNG FRIDGE SET ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/samsung-fridge/samsung-fridge-set/wlan/samsung-fridge-set.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/samsung-fridge/samsung-fridge-set/wlan/samsung-fridge-set-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/samsung-fridge/samsung-fridge-set/timestamps/samsung-fridge-set.timestamps"
DEVICE_IP="192.168.10.101"
ON_SIGNATURE="$OUTPUT_DIR/samsung-fridge/samsung-fridge-set/signatures/samsung-fridge-set-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/samsung-fridge/samsung-fridge-set/signatures/samsung-fridge-set-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/samsung-fridge/samsung-fridge-set/analyses/samsung-fridge-set-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/samsung-fridge/samsung-fridge-set/analyses/samsung-fridge-set-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="3,1,0"
DELETED_SEQUENCES_OFF="2,0"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.5 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =========================================== SAMSUNG FRIDGE VIEW INSIDE ===============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/samsung-fridge/samsung-fridge-viewinside/wlan/samsung-fridge-viewinside.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/samsung-fridge/samsung-fridge-viewinside/wlan/samsung-fridge-viewinside-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/samsung-fridge/samsung-fridge-viewinside/timestamps/samsung-fridge-viewinside.timestamps"
DEVICE_IP="192.168.10.101"
ON_SIGNATURE="$OUTPUT_DIR/samsung-fridge/samsung-fridge-viewinside/signatures/samsung-fridge-viewinside-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/samsung-fridge/samsung-fridge-viewinside/signatures/samsung-fridge-viewinside-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/samsung-fridge/samsung-fridge-viewinside/analyses/samsung-fridge-viewinside-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/samsung-fridge/samsung-fridge-viewinside/analyses/samsung-fridge-viewinside-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="1,1"
DELETED_SEQUENCES_OFF="1,1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.5 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= SAMSUNG-TV MENU ====================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/samsungtv-wired/samsungtv-wired-menu/wlan/samsungtv-wired-menu.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/samsungtv-wired/samsungtv-wired-menu/wlan/samsungtv-wired-menu-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/samsungtv-wired/samsungtv-wired-menu/timestamps/samsungtv-wired-menu.timestamps"
DEVICE_IP="192.168.10.121"
ON_SIGNATURE="$OUTPUT_DIR/samsungtv-wired/samsungtv-wired-menu/signatures/samsungtv-wired-menu-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/samsungtv-wired/samsungtv-wired-menu/signatures/samsungtv-wired-menu-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/samsungtv-wired/samsungtv-wired-menu/analyses/samsungtv-wired-menu-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/samsungtv-wired/samsungtv-wired-menu/analyses/samsungtv-wired-menu-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ========================================== SMARTER COFFEE MACHINE ON/OFF =============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/smarter-coffee-machine/smarter-coffee-machine-onoff/wlan/smarter-coffee-machine-onoff.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/smarter-coffee-machine/smarter-coffee-machine-onoff/wlan/smarter-coffee-machine-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/smarter-coffee-machine/smarter-coffee-machine-onoff/timestamps/smarter-coffee-machine-onoff.timestamps"
DEVICE_IP="192.168.20.102"
ON_SIGNATURE="$OUTPUT_DIR/smarter-coffee-machine/smarter-coffee-machine-onoff/signatures/smarter-coffee-machine-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/smarter-coffee-machine/smarter-coffee-machine-onoff/signatures/smarter-coffee-machine-onoff-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/smarter-coffee-machine/smarter-coffee-machine-onoff/analyses/smarter-coffee-machine-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/smarter-coffee-machine/smarter-coffee-machine-onoff/analyses/smarter-coffee-machine-onoff-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.99 and INCLUSION_WINDOW_MILLIS = 30_000
# TODO: However, the clusters are really small due to inconsistent traffic patterns (seems to be a PCAP-capturing problem on their end)
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ========================================== SMARTER COFFEE MACHINE WATER ==============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/smarter-coffee-machine/smarter-coffee-machine-water/wlan/smarter-coffee-machine-water.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/smarter-coffee-machine/smarter-coffee-machine-water/wlan/smarter-coffee-machine-water-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/smarter-coffee-machine/smarter-coffee-machine-water/timestamps/smarter-coffee-machine-water.timestamps"
DEVICE_IP="192.168.20.102"
ON_SIGNATURE="$OUTPUT_DIR/smarter-coffee-machine/smarter-coffee-machine-water/signatures/smarter-coffee-machine-water-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/smarter-coffee-machine/smarter-coffee-machine-water/signatures/smarter-coffee-machine-water-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/smarter-coffee-machine/smarter-coffee-machine-water/analyses/smarter-coffee-machine-water-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/smarter-coffee-machine/smarter-coffee-machine-water/analyses/smarter-coffee-machine-water-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.99 and INCLUSION_WINDOW_MILLIS = 30_000
# TODO: However, the clusters are really small due to inconsistent traffic patterns (seems to be a PCAP-capturing problem on their end)
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== SOUS VIDE =======================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/sousvide/wlan/sousvide.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/sousvide/wlan/sousvide-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/sousvide/timestamps/sousvide.timestamps"
DEVICE_IP="192.168.20.107"
ON_SIGNATURE="$OUTPUT_DIR/sousvide/signatures/sousvide-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/sousvide/signatures/sousvide-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/sousvide/analyses/sousvide-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/sousvide/analyses/sousvide-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: This comes from the UK side since the US side only has 3 triggers
# TODO: Big clusters (did not extract anything)---they seem to have their proprietary protocol over TCP
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== WANSVIEW CAMERA PHOTO ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/wansview-camera/wansview-camera-photo/wlan/wansview-camera-photo.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/wansview-camera/wansview-camera-photo/wlan/wansview-camera-photo-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wansview-camera/wansview-camera-photo/timestamps/wansview-camera-photo.timestamps"
DEVICE_IP="192.168.10.226"
ON_SIGNATURE="$OUTPUT_DIR/wansview-camera/wansview-camera-photo/signatures/wansview-camera-photo-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/wansview-camera/wansview-camera-photo/signatures/wansview-camera-photo-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/wansview-camera/wansview-camera-photo/analyses/wansview-camera-photo-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/wansview-camera/wansview-camera-photo/analyses/wansview-camera-photo-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================= WANSVIEW CAMERA RECORDING ==============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/wansview-camera/wansview-camera-recording/wlan/wansview-camera-recording.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/wansview-camera/wansview-camera-recording/wlan/wansview-camera-recording-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wansview-camera/wansview-camera-recording/timestamps/wansview-camera-recording.timestamps"
DEVICE_IP="192.168.10.226"
ON_SIGNATURE="$OUTPUT_DIR/wansview-camera/wansview-camera-recording/signatures/wansview-camera-recording-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/wansview-camera/wansview-camera-recording/signatures/wansview-camera-recording-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/wansview-camera/wansview-camera-recording/analyses/wansview-camera-recording-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/wansview-camera/wansview-camera-recording/analyses/wansview-camera-recording-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== WANSVIEW CAMERA WATCH ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/wansview-camera/wansview-camera-watch/wlan/wansview-camera-watch.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/wansview-camera/wansview-camera-watch/wlan/wansview-camera-watch-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wansview-camera/wansview-camera-watch/timestamps/wansview-camera-watch.timestamps"
DEVICE_IP="192.168.10.226"
ON_SIGNATURE="$OUTPUT_DIR/wansview-camera/wansview-camera-watch/signatures/wansview-camera-watch-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/wansview-camera/wansview-camera-watch/signatures/wansview-camera-watch-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/wansview-camera/wansview-camera-watch/analyses/wansview-camera-watch-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/wansview-camera/wansview-camera-watch/analyses/wansview-camera-watch-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== WINK HUB COLOR ====================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/wink-hub/wink-hub-color/wlan/wink-hub-color.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/wink-hub/wink-hub-color/wlan/wink-hub-color-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wink-hub/wink-hub-color/timestamps/wink-hub-color.timestamps"
DEVICE_IP="192.168.10.148"
ON_SIGNATURE="$OUTPUT_DIR/wink-hub/wink-hub-color/signatures/wink-hub-color-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/wink-hub/wink-hub-color/signatures/wink-hub-color-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/wink-hub/wink-hub-color/analyses/wink-hub-color-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/wink-hub/wink-hub-color/analyses/wink-hub-color-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================ WINK HUB INTENSITY ==================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/wink-hub/wink-hub-intensity/wlan/wink-hub-intensity.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/wink-hub/wink-hub-intensity/wlan/wink-hub-intensity-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wink-hub/wink-hub-intensity/timestamps/wink-hub-intensity.timestamps"
DEVICE_IP="192.168.10.148"
ON_SIGNATURE="$OUTPUT_DIR/wink-hub/wink-hub-intensity/signatures/wink-hub-intensity-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/wink-hub/wink-hub-intensity/signatures/wink-hub-intensity-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/wink-hub/wink-hub-intensity/analyses/wink-hub-intensity-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/wink-hub/wink-hub-intensity/analyses/wink-hub-intensity-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="0"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== WINK HUB ON/OFF ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/wink-hub/wink-hub-onoff/wlan/wink-hub-onoff.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/wink-hub/wink-hub-onoff/wlan/wink-hub-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wink-hub/wink-hub-onoff/timestamps/wink-hub-onoff.timestamps"
DEVICE_IP="192.168.10.148"
ON_SIGNATURE="$OUTPUT_DIR/wink-hub/wink-hub-onoff/signatures/wink-hub-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/wink-hub/wink-hub-onoff/signatures/wink-hub-onoff-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/wink-hub/wink-hub-onoff/analyses/wink-hub-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/wink-hub/wink-hub-onoff/analyses/wink-hub-onoff-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =================================================== YI CAMERA PHOTO ==================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/yi-camera/yi-camera-photo/wlan/yi-camera-photo.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/yi-camera/yi-camera-photo/wlan/yi-camera-photo-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/yi-camera/yi-camera-photo/timestamps/yi-camera-photo.timestamps"
DEVICE_IP="192.168.10.204"
ON_SIGNATURE="$OUTPUT_DIR/yi-camera/yi-camera-photo/signatures/yi-camera-photo-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/yi-camera/yi-camera-photo/signatures/yi-camera-photo-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/yi-camera/yi-camera-photo/analyses/yi-camera-photo-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/yi-camera/yi-camera-photo/analyses/yi-camera-photo-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= YI CAMERA RECORDING ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/yi-camera/yi-camera-recording/wlan/yi-camera-recording.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/yi-camera/yi-camera-recording/wlan/yi-camera-recording-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/yi-camera/yi-camera-recording/timestamps/yi-camera-recording.timestamps"
DEVICE_IP="192.168.10.204"
ON_SIGNATURE="$OUTPUT_DIR/yi-camera/yi-camera-recording/signatures/yi-camera-recording-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/yi-camera/yi-camera-recording/signatures/yi-camera-recording-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/yi-camera/yi-camera-recording/analyses/yi-camera-recording-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/yi-camera/yi-camera-recording/analyses/yi-camera-recording-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =================================================== YI CAMERA WATCH ==================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/yi-camera/yi-camera-watch/wlan/yi-camera-watch.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/yi-camera/yi-camera-watch/wlan/yi-camera-watch-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/yi-camera/yi-camera-watch/timestamps/yi-camera-watch.timestamps"
DEVICE_IP="192.168.10.204"
ON_SIGNATURE="$OUTPUT_DIR/yi-camera/yi-camera-watch/signatures/yi-camera-watch-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/yi-camera/yi-camera-watch/signatures/yi-camera-watch-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/yi-camera/yi-camera-watch/analyses/yi-camera-watch-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/yi-camera/yi-camera-watch/analyses/yi-camera-watch-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== ZMODO DOORBELL PHOTO ==================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/zmodo-doorbell/zmodo-doorbell-photo/wlan/zmodo-doorbell-photo.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/zmodo-doorbell/zmodo-doorbell-photo/wlan/zmodo-doorbell-photo-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/zmodo-doorbell/zmodo-doorbell-photo/timestamps/zmodo-doorbell-photo.timestamps"
DEVICE_IP="192.168.10.236"
ON_SIGNATURE="$OUTPUT_DIR/zmodo-doorbell/zmodo-doorbell-photo/signatures/zmodo-doorbell-photo-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/zmodo-doorbell/zmodo-doorbell-photo/signatures/zmodo-doorbell-photo-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/zmodo-doorbell/zmodo-doorbell-photo/analyses/zmodo-doorbell-photo-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/zmodo-doorbell/zmodo-doorbell-photo/analyses/zmodo-doorbell-photo-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="1"
DELETED_SEQUENCES_OFF="0"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================ ZMODO DOORBELL RECORDING ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/zmodo-doorbell/zmodo-doorbell-recording/wlan/zmodo-doorbell-recording.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/zmodo-doorbell/zmodo-doorbell-recording/wlan/zmodo-doorbell-recording-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/zmodo-doorbell/zmodo-doorbell-recording/timestamps/zmodo-doorbell-recording.timestamps"
DEVICE_IP="192.168.10.236"
ON_SIGNATURE="$OUTPUT_DIR/zmodo-doorbell/zmodo-doorbell-recording/signatures/zmodo-doorbell-recording-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/zmodo-doorbell/zmodo-doorbell-recording/signatures/zmodo-doorbell-recording-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/zmodo-doorbell/zmodo-doorbell-recording/analyses/zmodo-doorbell-recording-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/zmodo-doorbell/zmodo-doorbell-recording/analyses/zmodo-doorbell-recording-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== ZMODO DOORBELL WATCH ==================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/zmodo-doorbell/zmodo-doorbell-watch/wlan/zmodo-doorbell-watch.wlan.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/zmodo-doorbell/zmodo-doorbell-watch/wlan/zmodo-doorbell-watch-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/zmodo-doorbell/zmodo-doorbell-watch/timestamps/zmodo-doorbell-watch.timestamps"
DEVICE_IP="192.168.10.236"
ON_SIGNATURE="$OUTPUT_DIR/zmodo-doorbell/zmodo-doorbell-watch/signatures/zmodo-doorbell-watch-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/zmodo-doorbell/zmodo-doorbell-watch/signatures/zmodo-doorbell-watch-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/zmodo-doorbell/zmodo-doorbell-watch/analyses/zmodo-doorbell-watch-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/zmodo-doorbell/zmodo-doorbell-watch/analyses/zmodo-doorbell-watch-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

# TODO: Need to change CLUSTER_BOUNDS_MULTIPLIER to 0.2 and INCLUSION_WINDOW_MILLIS = 30_000
PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
