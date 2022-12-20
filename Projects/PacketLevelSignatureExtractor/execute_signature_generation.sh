#!/bin/bash

#set -x # echo invoked commands to std out

# Base dir should point to the experimental_result folder which contains the subfolders:
# - 'smarthome' which contains the traces collected while other devices are idle
# - 'standalone' which contains signatures and the traces used to generate the signatures.
BASE_DIR=$1
readonly BASE_DIR

OUTPUT_DIR=$2
readonly OUTPUT_DIR

SIGNATURES_BASE_DIR="$BASE_DIR/standalone"
readonly SIGNATURES_BASE_DIR

# =================================================== AMAZON PLUG ======================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/amazon-plug/wlan1/amazon-plug.wlan1.local.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/amazon-plug/wlan1/amazon-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/amazon-plug/timestamps/amazon-plug-apr-16-2019.timestamps"
DEVICE_IP="192.168.1.189"
ON_SIGNATURE="$OUTPUT_DIR/amazon-plug/signatures/amazon-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/amazon-plug/signatures/amazon-plug-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/amazon-plug/analyses/amazon-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/amazon-plug/analyses/amazon-plug-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
INPUT_PCAP="$SIGNATURES_BASE_DIR/amazon-plug/wlan1/amazon-plug.wlan1.remote.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/amazon-plug/wlan1/amazon-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/amazon-plug/timestamps/amazon-plug-dec-6-2019.timestamps"
DEVICE_IP="192.168.1.189"
ON_SIGNATURE="$OUTPUT_DIR/amazon-plug/signatures/amazon-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/amazon-plug/signatures/amazon-plug-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/amazon-plug/analyses/amazon-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/amazon-plug/analyses/amazon-plug-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="2"
DELETED_SEQUENCES_OFF="2"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== ARLO CAMERA =====================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/arlo-camera/wlan1/arlo-camera.wlan1.local.pcap"

# Has no device side signature.
# PHONE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/arlo-camera/wlan1/arlo-camera-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/arlo-camera/timestamps/arlo-camera-nov-13-2018.timestamps"
DEVICE_IP="192.168.1.246"
ON_SIGNATURE="$OUTPUT_DIR/arlo-camera/signatures/arlo-camera-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/arlo-camera/signatures/arlo-camera-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/arlo-camera/analyses/arlo-camera-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/arlo-camera/analyses/arlo-camera-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT - start recording feature
INPUT_PCAP="$SIGNATURES_BASE_DIR/arlo-camera/arlo-camera-startrecording/wlan1/arlo-camera-startrecording.wlan1.ifttt.pcap"

# DEVICE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/arlo-camera/arlo-camera-startrecording/wlan1/arlo-camera-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/arlo-camera/arlo-camera-startrecording/timestamps/arlo-camera-startrecording-ifttt-dec-15-2019.timestamps"
DEVICE_IP="192.168.1.142"
ON_SIGNATURE="$OUTPUT_DIR/arlo-camera/arlo-camera-startrecording/signatures/arlo-camera-startrecording-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/arlo-camera/arlo-camera-startrecording/signatures/arlo-camera-startrecording-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/arlo-camera/arlo-camera-startrecording/analyses/arlo-camera-startrecording-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/arlo-camera/arlo-camera-startrecording/analyses/arlo-camera-startrecording-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="2,0"
DELETED_SEQUENCES_OFF="2,1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================= BLOSSOM SPRINKLER QUICK RUN ============================================
# DEVICE SIDE
INPUT_PCAP="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/wlan1/blossom-sprinkler-quickrun.wlan1.local.pcap"
OUTPUT_PCAP="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/wlan1/blossom-sprinkler-quickrun-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/timestamps/blossom-sprinkler-quickrun-jan-14-2019.timestamps"
DEVICE_IP="192.168.1.229"
ON_SIGNATURE="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/signatures/blossom-sprinkler-quickrun-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/signatures/blossom-sprinkler-quickrun-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/analyses/blossom-sprinkler-quickrun-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/analyses/blossom-sprinkler-quickrun-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="2"
DELETED_SEQUENCES_OFF="3"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"

# PHONE SIDE
DEVICE_IP="192.168.1.246"
ON_SIGNATURE="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/signatures/blossom-sprinkler-quickrun-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/signatures/blossom-sprinkler-quickrun-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/analyses/blossom-sprinkler-quickrun-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/analyses/blossom-sprinkler-quickrun-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="0"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== BLOSSOM SPRINKLER MODE ===============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/wlan1/blossom-sprinkler-mode.wlan1.local.pcap"

# PHONE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-mode/wlan1/blossom-sprinkler-mode-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/timestamps/blossom-sprinkler-mode-apr-15-2019.timestamps"
DEVICE_IP="192.168.1.246"
ON_SIGNATURE="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-mode/signatures/blossom-sprinkler-mode-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-mode/signatures/blossom-sprinkler-mode-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-mode/analyses/blossom-sprinkler-mode-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-mode/analyses/blossom-sprinkler-mode-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="1,1,1"
DELETED_SEQUENCES_OFF="2,2,2"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"

# DEVICE SIDE
# TODO: For some reason there is no OFF signature for the device side, so we do not report it for now
DEVICE_IP="192.168.1.229"
ON_SIGNATURE="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-mode/signatures/blossom-sprinkler-mode-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-mode/signatures/blossom-sprinkler-mode-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-mode/analyses/blossom-sprinkler-mode-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-mode/analyses/blossom-sprinkler-mode-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="2"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== D-LINK PLUG =====================================================
# LOCAL
# DEVICE SIDE
INPUT_PCAP="$SIGNATURES_BASE_DIR/dlink-plug/wlan1/dlink-plug.wlan1.local.pcap"
OUTPUT_PCAP="$OUTPUT_DIR/dlink-plug/wlan1/dlink-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/dlink-plug/timestamps/dlink-plug-nov-7-2018.timestamps"
DEVICE_IP="192.168.1.199"
ON_SIGNATURE="$OUTPUT_DIR/dlink-plug/signatures/dlink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/dlink-plug/signatures/dlink-plug-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/dlink-plug/analyses/dlink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/dlink-plug/analyses/dlink-plug-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"

# PHONE SIDE
DEVICE_IP="192.168.1.246"
ON_SIGNATURE="$OUTPUT_DIR/dlink-plug/signatures/dlink-plug-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/dlink-plug/signatures/dlink-plug-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/dlink-plug/analyses/dlink-plug-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/dlink-plug/analyses/dlink-plug-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
# DEVICE SIDE
INPUT_PCAP="$SIGNATURES_BASE_DIR/dlink-plug/wlan1/dlink-plug.wlan1.remote.pcap"
OUTPUT_PCAP="$OUTPUT_DIR/dlink-plug/wlan1/dlink-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/dlink-plug/timestamps/dlink-plug-dec-2-2019.timestamps"
DEVICE_IP="192.168.1.199"
ON_SIGNATURE="$OUTPUT_DIR/dlink-plug/signatures/dlink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/dlink-plug/signatures/dlink-plug-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/dlink-plug/analyses/dlink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/dlink-plug/analyses/dlink-plug-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
# DEVICE SIDE
INPUT_PCAP="$SIGNATURES_BASE_DIR/dlink-plug/wlan1/dlink-plug.wlan1.ifttt.pcap"
OUTPUT_PCAP="$OUTPUT_DIR/dlink-plug/wlan1/dlink-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/dlink-plug/timestamps/dlink-plug-ifttt-dec-11-2019.timestamps"
DEVICE_IP="192.168.1.199"
ON_SIGNATURE="$OUTPUT_DIR/dlink-plug/signatures/dlink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/dlink-plug/signatures/dlink-plug-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/dlink-plug/analyses/dlink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/dlink-plug/analyses/dlink-plug-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="0"
DELETED_SEQUENCES_OFF="0"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== D-LINK SIREN ====================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/dlink-siren/wlan1/dlink-siren.wlan1.local.pcap"

# Has no device side signature.
# PHONE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/dlink-siren/wlan1/dlink-siren-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/dlink-siren/timestamps/dlink-siren-nov-9-2018.timestamps"
DEVICE_IP="192.168.1.246"
ON_SIGNATURE="$OUTPUT_DIR/dlink-siren/signatures/dlink-siren-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/dlink-siren/signatures/dlink-siren-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/dlink-siren/analyses/dlink-siren-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/dlink-siren/analyses/dlink-siren-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/dlink-siren/wlan1/dlink-siren.wlan1.ifttt.pcap"

# Has no device side signature.
# DEVICE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/dlink-siren/wlan1/dlink-siren-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/dlink-siren/timestamps/dlink-siren-ifttt-dec-14-2019.timestamps"
DEVICE_IP="192.168.1.184"
ON_SIGNATURE="$OUTPUT_DIR/dlink-siren/signatures/dlink-siren-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/dlink-siren/signatures/dlink-siren-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/dlink-siren/analyses/dlink-siren-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/dlink-siren/analyses/dlink-siren-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== ECOBEE THERMOSTAT HVAC ===============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/wlan1/ecobee-thermostat-hvac.wlan1.local.pcap"

# Phone Signature
OUTPUT_PCAP="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-hvac/wlan1/ecobee-thermostat-hvac-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/timestamps/ecobee-thermostat-hvac-apr-17-2019.timestamps"
DEVICE_IP="192.168.1.130"
ON_SIGNATURE="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-hvac/signatures/ecobee-thermostat-hvac-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-hvac/signatures/ecobee-thermostat-hvac-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-hvac/analyses/ecobee-thermostat-hvac-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-hvac/analyses/ecobee-thermostat-hvac-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="1,1,1"
DELETED_SEQUENCES_OFF="1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== ECOBEE THERMOSTAT FAN ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/wlan1/ecobee-thermostat-fan.wlan1.local.pcap"

# Phone Signature
OUTPUT_PCAP="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-fan/wlan1/ecobee-thermostat-fan-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/timestamps/ecobee-thermostat-fan-apr-18-2019.timestamps"
DEVICE_IP="192.168.1.130"
ON_SIGNATURE="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-fan/signatures/ecobee-thermostat-fan-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-fan/signatures/ecobee-thermostat-fan-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-fan/analyses/ecobee-thermostat-fan-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-fan/analyses/ecobee-thermostat-fan-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="1,1"
DELETED_SEQUENCES_OFF="1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ======================================================= HUE BULB =====================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/hue-bulb/eth1/hue-bulb.eth1.local.pcap"

# DEVICE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/hue-bulb/eth1/hue-bulb-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/hue-bulb/timestamps/hue-bulb-sept-11-2019.timestamps"
DEVICE_IP="192.168.1.100"
ON_SIGNATURE="$OUTPUT_DIR/hue-bulb/signatures/hue-bulb-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/hue-bulb/signatures/hue-bulb-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/hue-bulb/analyses/hue-bulb-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/hue-bulb/analyses/hue-bulb-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== HUE BULB ON/OFF ===================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-onoff/eth1/hue-bulb-onoff.eth1.ifttt.pcap"

# DEVICE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/hue-bulb/hue-bulb-onoff/eth1/hue-bulb-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-onoff/timestamps/hue-bulb-onoff-ifttt-dec-15-2019.timestamps"
DEVICE_IP="192.168.1.101"
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

# ================================================ HUE BULB INTENSITY ==================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-intensity/eth1/hue-bulb-intensity.eth1.ifttt.pcap"

# TODO: THE LOW INTENSITY PART SEEMS TO BE MISSING THE TRAILING C-378
# TODO: WE CAN TWEAK THE CODE AND ALLOW THE FOLLOWING LINES
# int lowerBound = numberOfEventsPerType - (int)(numberOfEventsPerType * 0.2);
# int upperBound = numberOfEventsPerType + (int)(numberOfEventsPerType * 0.2);
# DEVICE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/hue-bulb/hue-bulb-intensity/eth1/hue-bulb-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-intensity/timestamps/hue-bulb-intensity-ifttt-dec-20-2019.timestamps"
DEVICE_IP="192.168.1.100"
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

# ================================================= KWIKSET DOORLOCK ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/kwikset-doorlock/wlan1/kwikset-doorlock.wlan1.local.pcap"

# Has no device side signature.
# PHONE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/kwikset-doorlock/wlan1/kwikset-doorlock-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/kwikset-doorlock/timestamps/kwikset-doorlock-nov-10-2018.timestamps"
DEVICE_IP="192.168.1.246"
ON_SIGNATURE="$OUTPUT_DIR/kwikset-doorlock/signatures/kwikset-doorlock-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/kwikset-doorlock/signatures/kwikset-doorlock-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/kwikset-doorlock/analyses/kwikset-doorlock-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/kwikset-doorlock/analyses/kwikset-doorlock-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= NEST THERMOSTAT ====================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/nest-thermostat/wlan1/nest-thermostat.wlan1.local.pcap"

# Has no device side signature.
# PHONE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/nest-thermostat/wlan1/nest-thermostat-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/nest-thermostat/timestamps/nest-thermostat-nov-15-2018.timestamps"
DEVICE_IP="192.168.1.246"
ON_SIGNATURE="$OUTPUT_DIR/nest-thermostat/signatures/nest-thermostat-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/nest-thermostat/signatures/nest-thermostat-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/nest-thermostat/analyses/nest-thermostat-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/nest-thermostat/analyses/nest-thermostat-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== RACHIO SPRINKLER QUICK RUN ============================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun.wlan1.local.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/timestamps/rachio-sprinkler-quickrun-apr-18-2019.timestamps"
DEVICE_IP="192.168.1.143"
ON_SIGNATURE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/signatures/rachio-sprinkler-quickrun-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/signatures/rachio-sprinkler-quickrun-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/analyses/rachio-sprinkler-quickrun-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/analyses/rachio-sprinkler-quickrun-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
INPUT_PCAP="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun.wlan1.remote.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/timestamps/rachio-sprinkler-quickrun-dec-4-2019.timestamps"
DEVICE_IP="192.168.1.143"
ON_SIGNATURE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/signatures/rachio-sprinkler-quickrun-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/signatures/rachio-sprinkler-quickrun-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/analyses/rachio-sprinkler-quickrun-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/analyses/rachio-sprinkler-quickrun-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun.wlan1.ifttt.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/timestamps/rachio-sprinkler-quickrun-ifttt-dec-12-2019.timestamps"
DEVICE_IP="192.168.1.144"
ON_SIGNATURE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/signatures/rachio-sprinkler-quickrun-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/signatures/rachio-sprinkler-quickrun-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/analyses/rachio-sprinkler-quickrun-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/analyses/rachio-sprinkler-quickrun-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= RACHIO SPRINKLER MODE ==============================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/wlan1/rachio-sprinkler-mode.wlan1.local.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-mode/wlan1/rachio-sprinkler-mode-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/timestamps/rachio-sprinkler-mode-apr-18-2019.timestamps"
DEVICE_IP="192.168.1.143"
ON_SIGNATURE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-mode/signatures/rachio-sprinkler-mode-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-mode/signatures/rachio-sprinkler-mode-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-mode/analyses/rachio-sprinkler-mode-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-mode/analyses/rachio-sprinkler-mode-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
INPUT_PCAP="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/wlan1/rachio-sprinkler-mode.wlan1.remote.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-mode/wlan1/rachio-sprinkler-mode-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/timestamps/rachio-sprinkler-mode-dec-4-2019.timestamps"
DEVICE_IP="192.168.1.143"
ON_SIGNATURE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-mode/signatures/rachio-sprinkler-mode-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-mode/signatures/rachio-sprinkler-mode-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-mode/analyses/rachio-sprinkler-mode-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-mode/analyses/rachio-sprinkler-mode-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ===================================================== RING ALARM =====================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/ring-alarm/wlan1/ring-alarm.wlan1.local.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/ring-alarm/wlan1/alarm-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/ring-alarm/timestamps/ring-alarm-apr-26-2019.timestamps"
DEVICE_IP="192.168.1.113"
ON_SIGNATURE="$OUTPUT_DIR/ring-alarm/signatures/ring-alarm-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/ring-alarm/signatures/ring-alarm-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/ring-alarm/analyses/ring-alarm-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/ring-alarm/analyses/ring-alarm-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
INPUT_PCAP="$SIGNATURES_BASE_DIR/ring-alarm/wlan1/ring-alarm.wlan1.remote.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/ring-alarm/wlan1/alarm-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/ring-alarm/timestamps/ring-alarm-dec-9-2019.timestamps"
DEVICE_IP="192.168.1.113"
ON_SIGNATURE="$OUTPUT_DIR/ring-alarm/signatures/ring-alarm-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/ring-alarm/signatures/ring-alarm-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/ring-alarm/analyses/ring-alarm-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/ring-alarm/analyses/ring-alarm-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= ROOMBA VACUUM ROBOT ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/wlan1/roomba-vacuum-robot.wlan1.local.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/roomba-vacuum-robot/wlan1/roomba-vacuum-robot-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/timestamps/roomba-vacuum-robot-apr-25-2019.timestamps"
DEVICE_IP="192.168.1.246"
ON_SIGNATURE="$OUTPUT_DIR/roomba-vacuum-robot/signatures/roomba-vacuum-robot-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/roomba-vacuum-robot/signatures/roomba-vacuum-robot-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/roomba-vacuum-robot/analyses/roomba-vacuum-robot-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/roomba-vacuum-robot/analyses/roomba-vacuum-robot-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="0"
DELETED_SEQUENCES_OFF="0"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== SENGLED BULB ON/OFF ==================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/wlan1/sengled-bulb-onoff.wlan1.local.pcap"

# Phone Signature
OUTPUT_PCAP="$OUTPUT_DIR/sengled-bulb/sengled-bulb-onoff/wlan1/sengled-bulb-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/timestamps/sengled-bulb-onoff-apr-24-2019.timestamps"
DEVICE_IP="192.168.1.246"
ON_SIGNATURE="$OUTPUT_DIR/sengled-bulb/sengled-bulb-onoff/signatures/sengled-bulb-onoff-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/sengled-bulb/sengled-bulb-onoff/signatures/sengled-bulb-onoff-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/sengled-bulb/sengled-bulb-onoff/analyses/sengled-bulb-onoff-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/sengled-bulb/sengled-bulb-onoff/analyses/sengled-bulb-onoff-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"

# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/eth1/sengled-bulb-onoff.eth1.local.pcap"

# Device Signature
DEVICE_IP="192.168.1.201"
ON_SIGNATURE="$OUTPUT_DIR/sengled-bulb/sengled-bulb-onoff/signatures/sengled-bulb-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/sengled-bulb/sengled-bulb-onoff/signatures/sengled-bulb-onoff-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/sengled-bulb/sengled-bulb-onoff/analyses/sengled-bulb-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/sengled-bulb/sengled-bulb-onoff/analyses/sengled-bulb-onoff-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== SENGLED BULB INTENSITY ===============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/wlan1/sengled-bulb-intensity.wlan1.local.pcap"

# Phone Signature
OUTPUT_PCAP="$OUTPUT_DIR/sengled-bulb/sengled-bulb-intensity/wlan1/sengled-bulb-intensity-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/timestamps/sengled-bulb-intensity-apr-17-2019.timestamps"
DEVICE_IP="192.168.1.246"
ON_SIGNATURE="$OUTPUT_DIR/sengled-bulb/sengled-bulb-intensity/signatures/sengled-bulb-intensity-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/sengled-bulb/sengled-bulb-intensity/signatures/sengled-bulb-intensity-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/sengled-bulb/sengled-bulb-intensity/analyses/sengled-bulb-intensity-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/sengled-bulb/sengled-bulb-intensity/analyses/sengled-bulb-intensity-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"

# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/eth1/sengled-bulb-intensity.eth1.local.pcap"

# Device Signature
DEVICE_IP="192.168.1.201"
ON_SIGNATURE="$OUTPUT_DIR/sengled-bulb/sengled-bulb-intensity/signatures/sengled-bulb-intensity-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/sengled-bulb/sengled-bulb-intensity/signatures/sengled-bulb-intensity-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/sengled-bulb/sengled-bulb-intensity/analyses/sengled-bulb-intensity-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/sengled-bulb/sengled-bulb-intensity/analyses/sengled-bulb-intensity-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ====================================================== ST PLUG =======================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/st-plug/wlan1/st-plug.wlan1.local.pcap"

# Has no device side signature.
# PHONE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/st-plug/wlan1/st-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/st-plug/timestamps/st-plug-nov-12-2018.timestamps"
DEVICE_IP="192.168.1.246"
ON_SIGNATURE="$OUTPUT_DIR/st-plug/signatures/st-plug-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/st-plug/signatures/st-plug-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/st-plug/analyses/st-plug-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/st-plug/analyses/st-plug-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= TP LINK BULB ON/OFF ================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff.wlan1.local.pcap"

# Has LAN signature.
OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-nov-16-2018.timestamps"
DEVICE_IP="192.168.1.246"
ON_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/signatures/tplink-bulb-onoff-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/signatures/tplink-bulb-onoff-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/analyses/tplink-bulb-onoff-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/analyses/tplink-bulb-onoff-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff.wlan1.ifttt.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-ifttt-dec-14-2019.timestamps"
DEVICE_IP="192.168.1.141"
ON_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/signatures/tplink-bulb-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/signatures/tplink-bulb-onoff-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/analyses/tplink-bulb-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/analyses/tplink-bulb-onoff-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= TP LINK BULB COLOR =================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/wlan1/tplink-bulb-color.wlan1.local.pcap"

# No signature found for both phone and device sides
OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/wlan1/tplink-bulb-color-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/timestamps/tplink-bulb-color-apr-12-2019.timestamps"
DEVICE_IP="192.168.1.246"
ON_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/signatures/tplink-bulb-color-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/signatures/tplink-bulb-color-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/analyses/tplink-bulb-color-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/analyses/tplink-bulb-color-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/wlan1/tplink-bulb-color.wlan1.ifttt.pcap"

# No signature found for both phone and device sides
OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/wlan1/tplink-bulb-color-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/timestamps/tplink-bulb-color-ifttt-dec-18-2019.timestamps"
DEVICE_IP="192.168.1.140"
ON_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/signatures/tplink-bulb-color-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/signatures/tplink-bulb-color-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/analyses/tplink-bulb-color-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/analyses/tplink-bulb-color-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== TP LINK BULB INTENSITY ===============================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/wlan1/tplink-bulb-intensity.wlan1.local.pcap"

# No signature found for both phone and device sides
OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/wlan1/tplink-bulb-intensity-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/timestamps/tplink-bulb-intensity-apr-29-2019.timestamps"
DEVICE_IP="192.168.1.246"
ON_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/signatures/tplink-bulb-intensity-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/signatures/tplink-bulb-intensity-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/analyses/tplink-bulb-intensity-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/analyses/tplink-bulb-intensity-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/wlan1/tplink-bulb-intensity.wlan1.ifttt.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/wlan1/tplink-bulb-intensity-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/timestamps/tplink-bulb-intensity-ifttt-dec-17-2019.timestamps"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/timestamps/tplink-bulb-intensity-ifttt-dec-18-2019.timestamps"
DEVICE_IP="192.168.1.140"
ON_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/signatures/tplink-bulb-intensity-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/signatures/tplink-bulb-intensity-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/analyses/tplink-bulb-intensity-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/analyses/tplink-bulb-intensity-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== TP-LINK PLUG ====================================================
# LOCAL
# DEVICE SIDE (both the 112, 115 and 556, 1293 sequences)
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-plug/wlan1/tplink-plug.wlan1.local.pcap"

# LAN signature.
OUTPUT_PCAP="$OUTPUT_DIR/tplink-plug/wlan1/tplink-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-plug/timestamps/tplink-plug-nov-8-2018.timestamps"
DEVICE_IP="192.168.1.159"
ON_SIGNATURE="$OUTPUT_DIR/tplink-plug/signatures/tplink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-plug/signatures/tplink-plug-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-plug/analyses/tplink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-plug/analyses/tplink-plug-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"


# DEVICE SIDE OUTBOUND (contains only those packets that go through the WAN port, i.e., only the 556, 1293 sequence)
# WAN signature.
ON_SIGNATURE="$OUTPUT_DIR/tplink-plug/signatures/tplink-plug-onSignature-device-side-outbound.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-plug/signatures/tplink-plug-offSignature-device-side-outbound.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-plug/analyses/tplink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-plug/analyses/tplink-plug-offClusters-device-side.cls"
DELETED_SEQUENCES_ON="0"
DELETED_SEQUENCES_OFF="0"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"

# Phone side does not make sense as it is merely a subset of the device side and does not differentiate ONs from OFFs.
# ======================================================================================================================
# REMOTE
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-plug/wlan1/tplink-plug.wlan1.remote.pcap"

# LAN signature.
OUTPUT_PCAP="$OUTPUT_DIR/tplink-plug/wlan1/tplink-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-plug/timestamps/tplink-plug-dec-2-2019.timestamps"
DEVICE_IP="192.168.1.159"
ON_SIGNATURE="$OUTPUT_DIR/tplink-plug/signatures/tplink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-plug/signatures/tplink-plug-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-plug/analyses/tplink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-plug/analyses/tplink-plug-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="1"
DELETED_SEQUENCES_OFF="1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-plug/wlan1/tplink-plug.wlan1.ifttt.pcap"

# LAN signature.
OUTPUT_PCAP="$OUTPUT_DIR/tplink-plug/wlan1/tplink-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-plug/timestamps/tplink-plug-ifttt-dec-10-2019.timestamps"
DEVICE_IP="192.168.1.159"
ON_SIGNATURE="$OUTPUT_DIR/tplink-plug/signatures/tplink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-plug/signatures/tplink-plug-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-plug/analyses/tplink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-plug/analyses/tplink-plug-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="1"
DELETED_SEQUENCES_OFF="1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== WEMO INSIGHT PLUG =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/wemo-insight-plug/wlan1/wemo-insight-plug.wlan1.local.pcap"

# Has LAN signature.
OUTPUT_PCAP="$OUTPUT_DIR/wemo-insight-plug/wlan1/wemo-insight-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wemo-insight-plug/timestamps/wemo-insight-plug-nov-21-2018.timestamps"
DEVICE_IP="192.168.1.246"
ON_SIGNATURE="$OUTPUT_DIR/wemo-insight-plug/signatures/wemo-insight-plug-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/wemo-insight-plug/signatures/wemo-insight-plug-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/wemo-insight-plug/analyses/wemo-insight-plug-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/wemo-insight-plug/analyses/wemo-insight-plug-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/wemo-insight-plug/wlan1/wemo-insight-plug.wlan1.ifttt.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/wemo-insight-plug/wlan1/wemo-insight-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wemo-insight-plug/timestamps/wemo-insight-plug-ifttt-dec-14-2019.timestamps"
DEVICE_IP="192.168.1.136"
ON_SIGNATURE="$OUTPUT_DIR/wemo-insight-plug/signatures/wemo-insight-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/wemo-insight-plug/signatures/wemo-insight-plug-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/wemo-insight-plug/analyses/wemo-insight-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/wemo-insight-plug/analyses/wemo-insight-plug-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ===================================================== WEMO PLUG ======================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/wemo-plug/wlan1/wemo-plug.wlan1.local.pcap"

# Has LAN signature.
OUTPUT_PCAP="$OUTPUT_DIR/wemo-plug/wlan1/wemo-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wemo-plug/timestamps/wemo-plug-nov-20-2018.timestamps"
DEVICE_IP="192.168.1.246"
ON_SIGNATURE="$OUTPUT_DIR/wemo-plug/signatures/wemo-plug-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/wemo-plug/signatures/wemo-plug-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/wemo-plug/analyses/wemo-plug-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/wemo-plug/analyses/wemo-plug-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/wemo-plug/wlan1/wemo-plug.wlan1.ifttt.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/wemo-plug/wlan1/wemo-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wemo-plug/timestamps/wemo-plug-ifttt-dec-16-2019.timestamps"
DEVICE_IP="192.168.1.146"
ON_SIGNATURE="$OUTPUT_DIR/wemo-plug/signatures/wemo-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/wemo-plug/signatures/wemo-plug-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/wemo-plug/analyses/wemo-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/wemo-plug/analyses/wemo-plug-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# TODO: SAME VENDOR OBSERVATION (TP-LINK DEVICES)
# TODO: Use PCAP files in the same-vendor folder
# =============================================== TP-LINK TWO-OUTLET PLUG ==============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-two-outlet-plug/wlan1/tplink-two-outlet-plug.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-two-outlet-plug/wlan1/tplink-two-outlet-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-two-outlet-plug/timestamps/tplink-two-outlet-plug-dec-22-2019.timestamps"
DEVICE_IP="192.168.1.178"
ON_SIGNATURE="$OUTPUT_DIR/tplink-two-outlet-plug/signatures/tplink-two-outlet-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-two-outlet-plug/signatures/tplink-two-outlet-plug-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-two-outlet-plug/analyses/tplink-two-outlet-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-two-outlet-plug/analyses/tplink-two-outlet-plug-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= TP-LINK POWER STRIP ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-power-strip/wlan1/tplink-power-strip.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-power-strip/wlan1/tplink-power-strip-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-power-strip/timestamps/tplink-power-strip-dec-22-2019.timestamps"
DEVICE_IP="192.168.1.142"
ON_SIGNATURE="$OUTPUT_DIR/tplink-power-strip/signatures/tplink-power-strip-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-power-strip/signatures/tplink-power-strip-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-power-strip/analyses/tplink-power-strip-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-power-strip/analyses/tplink-power-strip-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== TP-LINK LIGHT BULB ON/OFF =============================================
# KL-110 (newer model than LB-130 but no color---only dimmable white)
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb-white/tplink-bulb-white-onoff/wlan1/tplink-bulb-white-onoff.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb-white/tplink-bulb-white-onoff/wlan1/tplink-bulb-white-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb-white/tplink-bulb-white-onoff/timestamps/tplink-bulb-white-onoff-dec-21-2019.timestamps"
DEVICE_IP="192.168.1.227"
ON_SIGNATURE="$OUTPUT_DIR/tplink-bulb-white/tplink-bulb-white-onoff/signatures/tplink-bulb-white-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-bulb-white/tplink-bulb-white-onoff/signatures/tplink-bulb-white-onoff-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-bulb-white/tplink-bulb-white-onoff/analyses/tplink-bulb-white-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-bulb-white/tplink-bulb-white-onoff/analyses/tplink-bulb-white-onoff-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================= TP-LINK LIGHT BULB INTENSITY ===========================================
# KL-110 (newer model than LB-130 but no color---only dimmable white)
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb-white/tplink-bulb-white-intensity/wlan1/tplink-bulb-white-intensity.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb-white/tplink-bulb-white-intensity/wlan1/tplink-bulb-white-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb-white/tplink-bulb-white-intensity/timestamps/tplink-bulb-white-intensity-dec-21-2019.timestamps"
DEVICE_IP="192.168.1.227"
ON_SIGNATURE="$OUTPUT_DIR/tplink-bulb-white/tplink-bulb-white-intensity/signatures/tplink-bulb-white-intensity-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-bulb-white/tplink-bulb-white-intensity/signatures/tplink-bulb-white-intensity-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-bulb-white/tplink-bulb-white-intensity/analyses/tplink-bulb-white-intensity-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-bulb-white/tplink-bulb-white-intensity/analyses/tplink-bulb-white-intensity-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================ TP-LINK CAMERA ON/OFF ===============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-camera/tplink-camera-onoff/wlan1/tplink-camera-onoff.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-camera/tplink-camera-onoff/wlan1/tplink-light-camera-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-camera/tplink-camera-onoff/timestamps/tplink-camera-onoff-dec-22-2019.timestamps"
DEVICE_IP="192.168.1.235"
ON_SIGNATURE="$OUTPUT_DIR/tplink-camera/tplink-camera-onoff/signatures/tplink-camera-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-camera/tplink-camera-onoff/signatures/tplink-camera-onoff-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-camera/tplink-camera-onoff/analyses/tplink-camera-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-camera/tplink-camera-onoff/analyses/tplink-camera-onoff-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== TP-LINK CAMERA RECORDING =============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-camera/tplink-camera-recording/wlan1/tplink-camera-recording.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-camera/tplink-camera-recording/wlan1/tplink-light-camera-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-camera/tplink-camera-recording/timestamps/tplink-camera-recording-dec-22-2019.timestamps"
DEVICE_IP="192.168.1.235"
ON_SIGNATURE="$OUTPUT_DIR/tplink-camera/tplink-camera-recording/signatures/tplink-camera-recording-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-camera/tplink-camera-recording/signatures/tplink-camera-recording-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-camera/tplink-camera-recording/analyses/tplink-camera-recording-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-camera/tplink-camera-recording/analyses/tplink-camera-recording-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# TODO: Mon(IoT)r PUBLIC DATASET
# TODO: Use PCAP files in the public-dataset folder
# TODO: For the TP-Link plug and WeMo Insight plug, the PCAP files in this folder are the results of retraining in December 2019
# ==================================================== TP-LINK PLUG ====================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-plug/wlan1/tplink-plug.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-plug/wlan1/tplink-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-plug/timestamps/tplink-plug-retraining-dec-25-2019.timestamps"
DEVICE_IP="192.168.1.160"
ON_SIGNATURE="$OUTPUT_DIR/tplink-plug/signatures/tplink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/tplink-plug/signatures/tplink-plug-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/tplink-plug/analyses/tplink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/tplink-plug/analyses/tplink-plug-offClusters-device-side.cls"
EPSILON="10.0"
# TODO: Change the deleted sequences to 0 if we want to get just the outbound signatures
DELETED_SEQUENCES_ON="0"
DELETED_SEQUENCES_OFF="0"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== WEMO INSIGHT PLUG =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/wemo-insight-plug/wlan1/wemo-insight-plug.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/wemo-insight-plug/wlan1/wemo-insight-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wemo-insight-plug/timestamps/wemo-insight-plug-retraining-jan-9-2020.timestamps"
# The format 192.168.10 is needed to generate packet length 260
DEVICE_IP="192.168.10.246"
ON_SIGNATURE="$OUTPUT_DIR/wemo-insight-plug/signatures/wemo-insight-plug-onSignature-phone-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/wemo-insight-plug/signatures/wemo-insight-plug-offSignature-phone-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/wemo-insight-plug/analyses/wemo-insight-plug-onClusters-phone-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/wemo-insight-plug/analyses/wemo-insight-plug-offClusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="0"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# Mon(IoT)r DATASET
# ================================================= BLINK CAMERA WATCH =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-watch/wlan1/blink-camera-watch.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/blink-camera/blink-camera-watch/wlan1/blink-camera-watch-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-watch/timestamps/blink-camera-watch-retraining-dec-23-2019.timestamps"
DEVICE_IP="192.168.1.228"
ON_SIGNATURE="$OUTPUT_DIR/blink-camera/blink-camera-watch/signatures/blink-camera-watch-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/blink-camera/blink-camera-watch/signatures/blink-camera-watch-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/blink-camera/blink-camera-watch/analyses/blink-camera-watch-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/blink-camera/blink-camera-watch/analyses/blink-camera-watch-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= BLINK CAMERA PHOTO =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-photo/wlan1/blink-camera-photo.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/blink-camera/blink-camera-photo/wlan1/blink-camera-photo-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-photo/timestamps/blink-camera-photo-retraining-dec-24-2019.timestamps"
DEVICE_IP="192.168.1.228"
ON_SIGNATURE="$OUTPUT_DIR/blink-camera/blink-camera-photo/signatures/blink-camera-photo-onSignature-device-side.sig"
OFF_SIGNATURE="$OUTPUT_DIR/blink-camera/blink-camera-photo/signatures/blink-camera-photo-offSignature-device-side.sig"
ON_ANALYSIS="$OUTPUT_DIR/blink-camera/blink-camera-photo/analyses/blink-camera-photo-onClusters-device-side.cls"
OFF_ANALYSIS="$OUTPUT_DIR/blink-camera/blink-camera-photo/analyses/blink-camera-photo-offClusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES_ON="-1"
DELETED_SEQUENCES_OFF="-1"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES_ON' '$DELETED_SEQUENCES_OFF'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= ROOMBA VACUUM ROBOT ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/wlan1/roomba-vacuum-robot.wlan1.local.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/roomba-vacuum-robot/wlan1/roomba-vacuum-robot-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/timestamps/roomba-vacuum-robot-apr-25-2019.timestamps"
DEVICE_IP="192.168.1.246"
SIGNATURE="$OUTPUT_DIR/roomba-vacuum-robot/signatures/roomba-vacuum-robot-Signature-phone-side.sig"
ANALYSIS="$OUTPUT_DIR/roomba-vacuum-robot/analyses/roomba-vacuum-robot-Clusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/timestamps/roomba-vacuum-robot-apr-25-2019-deletedSequences.txt"
EVENT_TYPES="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/timestamps/roomba-vacuum-robot-apr-25-2019-eventTypes.txt"
EVENTS_OCCURED="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/timestamps/roomba-vacuum-robot-apr-25-2019-eventsOccured.txt"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$SIGNATURE' '$ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES' '$EVENT_TYPES' '$EVENTS_OCCURED'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# ================================================= TP LINK BULB ON/OFF ================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff.wlan1.local.pcap"

# Has LAN signature.
OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-nov-16-2018.timestamps"
DEVICE_IP="192.168.1.246"
SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/signatures/tplink-bulb-onoff-Signature-phone-side.sig"
ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/analyses/tplink-bulb-onoff-Clusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-nov-16-2018-deletedSequences.txt"
EVENT_TYPES="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-nov-16-2018-eventTypes.txt"
EVENTS_OCCURED="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-nov-16-2018-eventsOccured.txt"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$SIGNATURE' '$ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES' '$EVENT_TYPES' '$EVENTS_OCCURED'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# ===================================================== RING ALARM =====================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/ring-alarm/wlan1/ring-alarm.wlan1.local.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/ring-alarm/wlan1/alarm-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/ring-alarm/timestamps/ring-alarm-apr-26-2019.timestamps"
DEVICE_IP="192.168.1.113"
SIGNATURE="$OUTPUT_DIR/ring-alarm/signatures/ring-alarm-Signature-device-side.sig"
ANALYSIS="$OUTPUT_DIR/ring-alarm/analyses/ring-alarm-Clusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES="$SIGNATURES_BASE_DIR/ring-alarm/timestamps/ring-alarm-apr-26-2019-deletedSequences.txt"
EVENT_TYPES="$SIGNATURES_BASE_DIR/ring-alarm/timestamps/ring-alarm-apr-26-2019-eventTypes.txt"
EVENTS_OCCURED="$SIGNATURES_BASE_DIR/ring-alarm/timestamps/ring-alarm-apr-26-2019-eventsOccured.txt"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$SIGNATURE' '$ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES' '$EVENT_TYPES' '$EVENTS_OCCURED'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# ================================================= TP LINK BULB ON/OFF ================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff.wlan1.local.pcap"

# Has LAN signature.
OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-nov-16-2018.timestamps"
DEVICE_IP="192.168.1.246"
SIGNATURE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/signatures/tplink-bulb-onoff-Signature-phone-side.sig"
ANALYSIS="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/analyses/tplink-bulb-onoff-Clusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-nov-16-2018-deletedSequences.txt"
EVENT_TYPES="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-nov-16-2018-eventTypes.txt"
EVENTS_OCCURED="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-nov-16-2018-eventsOccured.txt"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$SIGNATURE' '$ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES' '$EVENT_TYPES' '$EVENTS_OCCURED'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# ================================================= ROOMBA VACUUM ROBOT ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/wlan1/roomba-vacuum-robot.wlan1.local.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/roomba-vacuum-robot/wlan1/roomba-vacuum-robot-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/timestamps/roomba-vacuum-robot-apr-25-2019.timestamps"
DEVICE_IP="192.168.1.246"
SIGNATURE="$OUTPUT_DIR/roomba-vacuum-robot/signatures/roomba-vacuum-robot-Signature-phone-side.sig"
ANALYSIS="$OUTPUT_DIR/roomba-vacuum-robot/analyses/roomba-vacuum-robot-Clusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/timestamps/roomba-vacuum-robot-apr-25-2019-deletedSequences.txt"
EVENT_TYPES="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/timestamps/roomba-vacuum-robot-apr-25-2019-eventTypes.txt"
EVENTS_OCCURED="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/timestamps/roomba-vacuum-robot-apr-25-2019-eventsOccured.txt"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$SIGNATURE' '$ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES' '$EVENT_TYPES' '$EVENTS_OCCURED'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# ==================================================== ARLO CAMERA =====================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/arlo-camera/wlan1/arlo-camera.wlan1.local.pcap"

# Has no device side signature.
# PHONE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/arlo-camera/wlan1/arlo-camera-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/arlo-camera/timestamps/arlo-camera-nov-13-2018.timestamps"
DEVICE_IP="192.168.1.246"
SIGNATURE="$OUTPUT_DIR/arlo-camera/signatures/arlo-camera-Signature-phone-side.sig"
ANALYSIS="$OUTPUT_DIR/arlo-camera/analyses/arlo-camera-Clusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES="$SIGNATURES_BASE_DIR/arlo-camera/timestamps/arlo-camera-nov-13-2018-deletedSequences.txt"
EVENT_TYPES="$SIGNATURES_BASE_DIR/arlo-camera/timestamps/arlo-camera-nov-13-2018-eventTypes.txt"
EVENTS_OCCURED="$SIGNATURES_BASE_DIR/arlo-camera/timestamps/arlo-camera-nov-13-2018-eventsOccured.txt"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$SIGNATURE' '$ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES' '$EVENT_TYPES' '$EVENTS_OCCURED'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# ===================================================== WEMO PLUG ======================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/wemo-plug/wlan1/wemo-plug.wlan1.local.pcap"

# Has LAN signature.
OUTPUT_PCAP="$OUTPUT_DIR/wemo-plug/wlan1/wemo-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wemo-plug/timestamps/wemo-plug-nov-20-2018.timestamps"
DEVICE_IP="192.168.1.246"
SIGNATURE="$OUTPUT_DIR/wemo-plug/signatures/wemo-plug-Signature-phone-side.sig"
ANALYSIS="$OUTPUT_DIR/wemo-plug/analyses/wemo-plug-Clusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES="$SIGNATURES_BASE_DIR/wemo-plug/timestamps/wemo-plug-nov-20-2018-deletedSequences.txt"
EVENT_TYPES="$SIGNATURES_BASE_DIR/wemo-plug/timestamps/wemo-plug-nov-20-2018-eventTypes.txt"
EVENTS_OCCURED="$SIGNATURES_BASE_DIR/wemo-plug/timestamps/wemo-plug-nov-20-2018-eventsOccured.txt"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$SIGNATURE' '$ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES' '$EVENT_TYPES' '$EVENTS_OCCURED'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= NEST THERMOSTAT ====================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/nest-thermostat/wlan1/nest-thermostat.wlan1.local.pcap"

# Has no device side signature.
# PHONE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/nest-thermostat/wlan1/nest-thermostat-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/nest-thermostat/timestamps/nest-thermostat-nov-15-2018.timestamps"
DEVICE_IP="192.168.1.246"
SIGNATURE="$OUTPUT_DIR/nest-thermostat/signatures/nest-thermostat-Signature-phone-side.sig"
ANALYSIS="$OUTPUT_DIR/nest-thermostat/analyses/nest-thermostat-Clusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES="$SIGNATURES_BASE_DIR/nest-thermostat/timestamps/nest-thermostat-nov-15-2018-deletedSequences.txt"
EVENT_TYPES="$SIGNATURES_BASE_DIR/nest-thermostat/timestamps/nest-thermostat-nov-15-2018-eventTypes.txt"
EVENTS_OCCURED="$SIGNATURES_BASE_DIR/nest-thermostat/timestamps/nest-thermostat-nov-15-2018-eventsOccured.txt"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$SIGNATURE' '$ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES' '$EVENT_TYPES' '$EVENTS_OCCURED'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# ==================================================== D-LINK PLUG =====================================================
# LOCAL
# DEVICE SIDE
INPUT_PCAP="$SIGNATURES_BASE_DIR/dlink-plug/wlan1/dlink-plug.wlan1.local.pcap"
OUTPUT_PCAP="$OUTPUT_DIR/dlink-plug/wlan1/dlink-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/dlink-plug/timestamps/dlink-plug-nov-7-2018.timestamps"
DEVICE_IP="192.168.1.199"
SIGNATURE="$OUTPUT_DIR/dlink-plug/signatures/dlink-plug-Signature-device-side.sig"
ANALYSIS="$OUTPUT_DIR/dlink-plug/analyses/dlink-plug-Clusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES="$SIGNATURES_BASE_DIR/dlink-plug/timestamps/dlink-plug-nov-7-2018-deletedSequences.txt"
EVENT_TYPES="$SIGNATURES_BASE_DIR/dlink-plug/timestamps/dlink-plug-nov-7-2018-eventTypes.txt"
EVENTS_OCCURED="$SIGNATURES_BASE_DIR/dlink-plug/timestamps/dlink-plug-nov-7-2018-eventsOccured.txt"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$SIGNATURE' '$ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES' '$EVENT_TYPES' '$EVENTS_OCCURED'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"

# =================================================== AMAZON PLUG ======================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/amazon-plug/wlan1/amazon-plug.wlan1.local.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/amazon-plug/wlan1/amazon-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/amazon-plug/timestamps/amazon-plug-apr-16-2019.timestamps"
DEVICE_IP="192.168.1.189"
SIGNATURE="$OUTPUT_DIR/amazon-plug/signatures/amazon-plug-Signature-device-side.sig"
ANALYSIS="$OUTPUT_DIR/amazon-plug/analyses/amazon-plug-Clusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES="$SIGNATURES_BASE_DIR/amazon-plug/timestamps/amazon-plug-apr-16-2019-deletedSequences.txt"
EVENT_TYPES="$SIGNATURES_BASE_DIR/amazon-plug/timestamps/amazon-plug-apr-16-2019-eventTypes.txt"
EVENTS_OCCURED="$SIGNATURES_BASE_DIR/amazon-plug/timestamps/amazon-plug-apr-16-2019-eventsOccured.txt"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$SIGNATURE' '$ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES' '$EVENT_TYPES' '$EVENTS_OCCURED'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# ==================================================== D-LINK SIREN ====================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/dlink-siren/wlan1/dlink-siren.wlan1.local.pcap"

# Has no device side signature.
# PHONE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/dlink-siren/wlan1/dlink-siren-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/dlink-siren/timestamps/dlink-siren-nov-9-2018.timestamps"
DEVICE_IP="192.168.1.246"
SIGNATURE="$OUTPUT_DIR/dlink-siren/signatures/dlink-siren-Signature-phone-side.sig"
ANALYSIS="$OUTPUT_DIR/dlink-siren/analyses/dlink-siren-Clusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES="$SIGNATURES_BASE_DIR/dlink-siren/timestamps/dlink-siren-nov-9-2018-deletedSequences.txt"
EVENT_TYPES="$SIGNATURES_BASE_DIR/dlink-siren/timestamps/dlink-siren-nov-9-2018-eventTypes.txt"
EVENTS_OCCURED="$SIGNATURES_BASE_DIR/dlink-siren/timestamps/dlink-siren-nov-9-2018-eventsOccured.txt"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$SIGNATURE' '$ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES' '$EVENT_TYPES' '$EVENTS_OCCURED'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# ================================================= KWIKSET DOORLOCK ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/kwikset-doorlock/wlan1/kwikset-doorlock.wlan1.local.pcap"

# Has no device side signature.
# PHONE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/kwikset-doorlock/wlan1/kwikset-doorlock-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/kwikset-doorlock/timestamps/kwikset-doorlock-nov-10-2018.timestamps"
DEVICE_IP="192.168.1.246"
SIGNATURE="$OUTPUT_DIR/kwikset-doorlock/signatures/kwikset-doorlock-Signature-phone-side.sig"
ANALYSIS="$OUTPUT_DIR/kwikset-doorlock/analyses/kwikset-doorlock-Clusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES="$SIGNATURES_BASE_DIR/kwikset-doorlock/timestamps/kwikset-doorlock-nov-10-2018-deletedSequences.txt"
EVENT_TYPES="$SIGNATURES_BASE_DIR/kwikset-doorlock/timestamps/kwikset-doorlock-nov-10-2018-eventTypes.txt"
EVENTS_OCCURED="$SIGNATURES_BASE_DIR/kwikset-doorlock/timestamps/kwikset-doorlock-nov-10-2018-eventsOccured.txt"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$SIGNATURE' '$ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES' '$EVENT_TYPES' '$EVENTS_OCCURED'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"
# ======================================================================================================================
# ==================================================== TP-LINK PLUG ====================================================
# LOCAL
# DEVICE SIDE (both the 112, 115 and 556, 1293 sequences)
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-plug/wlan1/tplink-plug.wlan1.local.pcap"

# LAN signature.
OUTPUT_PCAP="$OUTPUT_DIR/tplink-plug/wlan1/tplink-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-plug/timestamps/tplink-plug-nov-8-2018.timestamps"
DEVICE_IP="192.168.1.159"
SIGNATURE="$OUTPUT_DIR/tplink-plug/signatures/tplink-plug-Signature-device-side.sig"
ANALYSIS="$OUTPUT_DIR/tplink-plug/analyses/tplink-plug-Clusters-device-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES="$SIGNATURES_BASE_DIR/tplink-plug/timestamps/tplink-plug-nov-8-2018-deletedSequences.txt"
EVENT_TYPES="$SIGNATURES_BASE_DIR/tplink-plug/timestamps/tplink-plug-nov-8-2018-eventTypes.txt"
EVENTS_OCCURED="$SIGNATURES_BASE_DIR/tplink-plug/timestamps/tplink-plug-nov-8-2018-eventsOccured.txt"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$SIGNATURE' '$ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES' '$EVENT_TYPES' '$EVENTS_OCCURED'"
#./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"

# =============================================== SENGLED BULB ON/OFF ==================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/wlan1/sengled-bulb-onoff.wlan1.local.pcap"

# Phone Signature
OUTPUT_PCAP="$OUTPUT_DIR/sengled-bulb/sengled-bulb-onoff/wlan1/sengled-bulb-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/timestamps/sengled-bulb-onoff-apr-24-2019.timestamps"
DEVICE_IP="192.168.1.246"
SIGNATURE="$OUTPUT_DIR/sengled-bulb/sengled-bulb-onoff/signatures/sengled-bulb-onoff-Signature-phone-side.sig"
ANALYSIS="$OUTPUT_DIR/sengled-bulb/sengled-bulb-onoff/analyses/sengled-bulb-onoff-Clusters-phone-side.cls"
EPSILON="10.0"
DELETED_SEQUENCES="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/timestamps/sengled-bulb-onoff-apr-24-2019-deletedSequences.txt"
EVENT_TYPES="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/timestamps/sengled-bulb-onoff-apr-24-2019-eventTypes.txt"
EVENTS_OCCURED="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/timestamps/sengled-bulb-onoff-apr-24-2019-eventsOccured.txt"

PROGRAM_ARGS="'$INPUT_PCAP' '$OUTPUT_PCAP' '$TIMESTAMP_FILE' '$DEVICE_IP' '$SIGNATURE' '$ANALYSIS' '$EPSILON' '$DELETED_SEQUENCES' '$EVENT_TYPES' '$EVENTS_OCCURED'"
./gradlew run -DmainClass=edu.uci.iotproject.SignatureGenerator --args="$PROGRAM_ARGS"