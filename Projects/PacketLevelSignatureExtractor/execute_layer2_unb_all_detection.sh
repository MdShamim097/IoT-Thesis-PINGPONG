#!/bin/bash

#set -x # echo invoked commands to std out

# Arg1 should point to the UNB trace (PCAP w/o any expected events).
PCAP_FILE=$1
readonly PCAP_FILE

# Arg2 should point to the base directory  for signature files (i.e., /some/local/path/experimental_result/standalone)
SIGNATURES_BASE_DIR=$2
readonly SIGNATURES_BASE_DIR

# Arg3 should point to folder where the detection results for the UNB trace are to be output.
OUTPUT_DIR=$3
readonly OUTPUT_DIR

# ==================================================== AMAZON PLUG =====================================================

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/amazon-plug/analyses/amazon-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/amazon-plug/analyses/amazon-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/amazon-plug/signatures/amazon-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/amazon-plug/signatures/amazon-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/amazon-plug/amazon-plug.wlan1.validation.pcap___device-side.detectionresults"
SIGNATURE_DURATION="4990"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== ARLO CAMERA =====================================================
# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/arlo-camera/analyses/arlo-camera-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/arlo-camera/analyses/arlo-camera-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/arlo-camera/signatures/arlo-camera-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/arlo-camera/signatures/arlo-camera-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/arlo-camera/arlo-camera.eth0.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="548"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================= BLOSSOM SPRINKLER QUICK RUN ============================================
# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/analyses/blossom-sprinkler-quickrun-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/analyses/blossom-sprinkler-quickrun-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/signatures/blossom-sprinkler-quickrun-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/signatures/blossom-sprinkler-quickrun-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/blossom-sprinkler-quickrun.eth0.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="9274"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/analyses/blossom-sprinkler-quickrun-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/analyses/blossom-sprinkler-quickrun-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/signatures/blossom-sprinkler-quickrun-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/signatures/blossom-sprinkler-quickrun-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/blossom-sprinkler-quickrun.eth0.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="3670"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== BLOSSOM SPRINKLER MODE ===============================================

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/analyses/blossom-sprinkler-mode-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/analyses/blossom-sprinkler-mode-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/signatures/blossom-sprinkler-mode-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/signatures/blossom-sprinkler-mode-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-mode/blossom-sprinkler-mode.wlan1.validation.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="1977"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== D-LINK PLUG =====================================================
# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-plug/analyses/dlink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-plug/analyses/dlink-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-plug/signatures/dlink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-plug/signatures/dlink-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/dlink-plug/dlink-plug.eth0.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="8866"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-plug/analyses/dlink-plug-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-plug/analyses/dlink-plug-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-plug/signatures/dlink-plug-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-plug/signatures/dlink-plug-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/dlink-plug/dlink-plug.eth0.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="193"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== D-LINK SIREN ====================================================
# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-siren/analyses/dlink-siren-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-siren/analyses/dlink-siren-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-siren/signatures/dlink-siren-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-siren/signatures/dlink-siren-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/dlink-siren/dlink-siren.eth0.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="71"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== ECOBEE THERMOSTAT HVAC ===============================================

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/analyses/ecobee-thermostat-hvac-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/analyses/ecobee-thermostat-hvac-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/signatures/ecobee-thermostat-hvac-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/signatures/ecobee-thermostat-hvac-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-hvac/ecobee-thermostat-hvac.wlan1.validation.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="733"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"

# ======================================================================================================================

# =============================================== ECOBEE THERMOSTAT FAN ================================================

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/analyses/ecobee-thermostat-fan-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/analyses/ecobee-thermostat-fan-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/signatures/ecobee-thermostat-fan-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/signatures/ecobee-thermostat-fan-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-fan/ecobee-thermostat-fan.wlan1.validation.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="1953"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"

# ======================================================================================================================

# ===================================================== HUE BULB =======================================================
# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/hue-bulb/analyses/hue-bulb-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/hue-bulb/analyses/hue-bulb-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/hue-bulb/signatures/hue-bulb-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/hue-bulb/signatures/hue-bulb-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/hue-bulb/hue-bulb.eth0.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="27"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= KWIKSET DOORLOCK ===================================================
# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/kwikset-doorlock/analyses/kwikset-doorlock-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/kwikset-doorlock/analyses/kwikset-doorlock-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/kwikset-doorlock/signatures/kwikset-doorlock-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/kwikset-doorlock/signatures/kwikset-doorlock-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/kwikset-doorlock/kwikset-doorlock.eth0.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="3161"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= NEST THERMOSTAT ====================================================
# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/nest-thermostat/analyses/nest-thermostat-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/nest-thermostat/analyses/nest-thermostat-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/nest-thermostat/signatures/nest-thermostat-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/nest-thermostat/signatures/nest-thermostat-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/nest-thermostat/nest-thermostat.eth0.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="1179"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== RACHIO SPRINKLER QUICK RUN ============================================

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/analyses/rachio-sprinkler-quickrun-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/analyses/rachio-sprinkler-quickrun-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/signatures/rachio-sprinkler-quickrun-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/signatures/rachio-sprinkler-quickrun-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/rachio-sprinkler-quickrun.wlan1.validation.pcap___device-side.detectionresults"
SIGNATURE_DURATION="2695"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= RACHIO SPRINKLER MODE ==============================================
# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/analyses/rachio-sprinkler-mode-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/analyses/rachio-sprinkler-mode-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/signatures/rachio-sprinkler-mode-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/signatures/rachio-sprinkler-mode-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-mode/rachio-sprinkler-mode.wlan1.validation.pcap___device-side.detectionresults"
SIGNATURE_DURATION="2791"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ===================================================== RING ALARM =====================================================
# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/ring-alarm/analyses/ring-alarm-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/ring-alarm/analyses/ring-alarm-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/ring-alarm/signatures/ring-alarm-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/ring-alarm/signatures/ring-alarm-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/ring-alarm/ring-alarm.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="665"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= ROOMBA VACUUM ROBOT ================================================
# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/analyses/roomba-vacuum-robot-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/analyses/roomba-vacuum-robot-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/signatures/roomba-vacuum-robot-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/signatures/roomba-vacuum-robot-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/roomba-vacuum-robot/roomba-vacuum-robot.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="5959"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== SENGLED BULB ON/OFF ==================================================

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/analyses/sengled-bulb-onoff-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/analyses/sengled-bulb-onoff-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/signatures/sengled-bulb-onoff-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/signatures/sengled-bulb-onoff-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/sengled-bulb/sengled-bulb-onoff/sengled-bulb-onoff.wlan1.validation.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="10045"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== SENGLED BULB INTENSITY ===============================================

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/analyses/sengled-bulb-intensity-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/analyses/sengled-bulb-intensity-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/signatures/sengled-bulb-intensity-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/signatures/sengled-bulb-intensity-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/sengled-bulb/sengled-bulb-intensity/sengled-bulb-intensity.wlan1.validation.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="7888"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================


# ====================================================== ST PLUG =======================================================
# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/st-plug/analyses/st-plug-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/st-plug/analyses/st-plug-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/st-plug/signatures/st-plug-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/st-plug/signatures/st-plug-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/st-plug/st-plug.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="2445"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= TP LINK BULB ON/OFF ================================================
# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/analyses/tplink-bulb-onoff-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/analyses/tplink-bulb-onoff-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/signatures/tplink-bulb-onoff-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/signatures/tplink-bulb-onoff-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/tplink-bulb-onoff.wlan1.wifi-detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="162"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================ TP-LINK BULB COLOR ==================================================
# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/analyses/tplink-bulb-color-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/analyses/tplink-bulb-color-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/signatures/tplink-bulb-color-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/signatures/tplink-bulb-color-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/tplink-bulb-color.wlan1.wifi-detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="191"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== TP-LINK BULB INTENSITY ================================================
# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/analyses/tplink-bulb-intensity-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/analyses/tplink-bulb-intensity-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/signatures/tplink-bulb-intensity-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/signatures/tplink-bulb-intensity-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/tplink-bulb-intensity.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="233"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== TP-LINK PLUG ====================================================
# DEVICE SIDE (both the 112, 115 and 556, 1293 sequences)
ON_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-plug/analyses/tplink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-plug/analyses/tplink-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-plug/signatures/tplink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-plug/signatures/tplink-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/tplink-plug/tplink-plug.wlan1.wifi-detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="3660"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"

# Phone side does not make sense as it is merely a subset of the device side and does not differentiate ONs from OFFs.
# ======================================================================================================================
# RELAXED MATCHING
# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-plug/analyses/tplink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-plug/analyses/tplink-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-plug/signatures/tplink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-plug/signatures/tplink-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/tplink-plug/tplink-plug.wlan1.wifi-detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="902"
EPSILON="10.0"
MINUS_R="-r"
DELTA="21"
PACKETLIST="592,1234,593,1235"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$MINUS_R' '$DELTA' '$PACKETLIST'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== WEMO INSIGHT PLUG =================================================
# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/wemo-insight-plug/analyses/wemo-insight-plug-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/wemo-insight-plug/analyses/wemo-insight-plug-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/wemo-insight-plug/signatures/wemo-insight-plug-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/wemo-insight-plug/signatures/wemo-insight-plug-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/wemo-insight-plug/wemo-insight-plug.wlan1.wifi-detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="106"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ===================================================== WEMO PLUG ======================================================
# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/wemo-plug/analyses/wemo-plug-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/wemo-plug/analyses/wemo-plug-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/wemo-plug/signatures/wemo-plug-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/wemo-plug/signatures/wemo-plug-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/wemo-plug/wemo-plug.wlan1.wifi-detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="147"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================