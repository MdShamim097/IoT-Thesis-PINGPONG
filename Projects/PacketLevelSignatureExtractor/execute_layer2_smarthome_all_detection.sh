#!/bin/bash

#set -x # echo invoked commands to std out

# Base dir should point to the experimental_result folder which contains the subfolders:
# - 'smarthome' which contains the traces collected while other devices are idle
# - 'standalone' which contains signatures and the traces used to generate the signatures.
BASE_DIR=$1
readonly BASE_DIR

OUTPUT_DIR=$2
readonly OUTPUT_DIR

PCAPS_BASE_DIR="$BASE_DIR/smarthome"
readonly PCAPS_BASE_DIR

SIGNATURES_BASE_DIR="$BASE_DIR/standalone"
readonly SIGNATURES_BASE_DIR

# ==================================================== AMAZON PLUG =====================================================
PCAP_FILE="$PCAPS_BASE_DIR/amazon-plug/wlan1/amazon-plug.wlan1.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/amazon-plug/analyses/amazon-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/amazon-plug/analyses/amazon-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/amazon-plug/signatures/amazon-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/amazon-plug/signatures/amazon-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/amazon-plug/amazon-plug.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="4990"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
PCAP_FILE="$PCAPS_BASE_DIR/amazon-plug/wlan1/amazon-plug.wlan1.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/amazon-plug/analyses/amazon-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/amazon-plug/analyses/amazon-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/amazon-plug/signatures/amazon-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/amazon-plug/signatures/amazon-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/amazon-plug/amazon-plug.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="7051"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== ARLO CAMERA =====================================================
# LOCAL
PCAP_FILE="$PCAPS_BASE_DIR/arlo-camera/wlan1/arlo-camera.wlan1.detection.pcap"

# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/arlo-camera/analyses/arlo-camera-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/arlo-camera/analyses/arlo-camera-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/arlo-camera/signatures/arlo-camera-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/arlo-camera/signatures/arlo-camera-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/arlo-camera/arlo-camera.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="548"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
# We need to copy the OFF signature as an ON signature. There is one variation missing in the generated ON signature
# and the OFF signature has it. After all, both are for the same type of event (i.e., start recording)
PCAP_FILE="$PCAPS_BASE_DIR/arlo-camera/wlan1/arlo-camera.wlan1.ifttt.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/arlo-camera/analyses/arlo-camera-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/arlo-camera/analyses/arlo-camera-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/arlo-camera/signatures/arlo-camera-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/arlo-camera/signatures/arlo-camera-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/arlo-camera/arlo-camera.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="215"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================= BLOSSOM SPRINKLER QUICK RUN ============================================
PCAP_FILE="$PCAPS_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/wlan1/blossom-sprinkler-quickrun.wlan1.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/analyses/blossom-sprinkler-quickrun-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/analyses/blossom-sprinkler-quickrun-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/signatures/blossom-sprinkler-quickrun-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/signatures/blossom-sprinkler-quickrun-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/blossom-sprinkler-quickrun.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="9274"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/analyses/blossom-sprinkler-quickrun-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/analyses/blossom-sprinkler-quickrun-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/signatures/blossom-sprinkler-quickrun-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/signatures/blossom-sprinkler-quickrun-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/blossom-sprinkler-quickrun.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="3670"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== BLOSSOM SPRINKLER MODE ================================================
PCAP_FILE="$PCAPS_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/wlan1/blossom-sprinkler-mode.wlan1.detection.pcap"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/analyses/blossom-sprinkler-mode-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/analyses/blossom-sprinkler-mode-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/signatures/blossom-sprinkler-mode-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/signatures/blossom-sprinkler-mode-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-mode/blossom-sprinkler-mode.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="1977"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== D-LINK PLUG =====================================================
PCAP_FILE="$PCAPS_BASE_DIR/dlink-plug/wlan1/dlink-plug.wlan1.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-plug/analyses/dlink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-plug/analyses/dlink-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-plug/signatures/dlink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-plug/signatures/dlink-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/dlink-plug/dlink-plug.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="8866"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-plug/analyses/dlink-plug-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-plug/analyses/dlink-plug-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-plug/signatures/dlink-plug-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-plug/signatures/dlink-plug-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/dlink-plug/dlink-plug.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="193"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
PCAP_FILE="$PCAPS_BASE_DIR/dlink-plug/wlan1/dlink-plug.wlan1.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-plug/analyses/dlink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-plug/analyses/dlink-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-plug/signatures/dlink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-plug/signatures/dlink-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/dlink-plug/dlink-plug.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="6589"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
PCAP_FILE="$PCAPS_BASE_DIR/dlink-plug/wlan1/dlink-plug.wlan1.ifttt.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-plug/analyses/dlink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-plug/analyses/dlink-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-plug/signatures/dlink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-plug/signatures/dlink-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/dlink-plug/dlink-plug.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="7001"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== D-LINK SIREN ====================================================
# LOCAL
PCAP_FILE="$PCAPS_BASE_DIR/dlink-siren/wlan1/dlink-siren.wlan1.detection.pcap"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-siren/analyses/dlink-siren-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-siren/analyses/dlink-siren-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-siren/signatures/dlink-siren-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-siren/signatures/dlink-siren-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/dlink-siren/dlink-siren.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="71"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
PCAP_FILE="$PCAPS_BASE_DIR/dlink-siren/wlan1/dlink-siren.wlan1.ifttt.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-siren/analyses/dlink-siren-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-siren/analyses/dlink-siren-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-siren/signatures/dlink-siren-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-siren/signatures/dlink-siren-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/dlink-siren/dlink-siren.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="310"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== ECOBEE THERMOSTAT HVAC ===============================================
PCAP_FILE="$PCAPS_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/wlan1/ecobee-thermostat-hvac.wlan1.detection.pcap"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/analyses/ecobee-thermostat-hvac-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/analyses/ecobee-thermostat-hvac-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/signatures/ecobee-thermostat-hvac-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/signatures/ecobee-thermostat-hvac-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-hvac/ecobee-thermostat-hvac.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="733"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== ECOBEE THERMOSTAT FAN ================================================
PCAP_FILE="$PCAPS_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/wlan1/ecobee-thermostat-fan.wlan1.detection.pcap"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/analyses/ecobee-thermostat-fan-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/analyses/ecobee-thermostat-fan-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/signatures/ecobee-thermostat-fan-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/signatures/ecobee-thermostat-fan-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-fan/ecobee-thermostat-fan.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="1953"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== HUE BULB ON/OFF ===================================================
# TODO: NOT DETECTED BECAUSE IT'S ETH1 SIGNATURE (NOT WLAN)
# IFTTT
PCAP_FILE="$PCAPS_BASE_DIR/hue-bulb/hue-bulb-onoff/wlan1/hue-bulb-onoff.wlan1.ifttt.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-onoff/analyses/hue-bulb-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-onoff/analyses/hue-bulb-onoff-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-onoff/signatures/hue-bulb-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-onoff/signatures/hue-bulb-onoff-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/hue-bulb/hue-bulb-onoff/hue-bulb-onoff.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="84"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================ HUE BULB INTENSITY ==================================================
# TODO: NOT DETECTED BECAUSE IT'S ETH1 SIGNATURE (NOT WLAN)
# IFTTT
PCAP_FILE="$PCAPS_BASE_DIR/hue-bulb/hue-bulb-intensity/wlan1/hue-bulb-intensity.wlan1.ifttt.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-intensity/analyses/hue-bulb-intensity-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-intensity/analyses/hue-bulb-intensity-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-intensity/signatures/hue-bulb-intensity-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-intensity/signatures/hue-bulb-intensity-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/hue-bulb/hue-bulb-intensity/hue-bulb-intensity.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="106"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= KWIKSET DOORLOCK ===================================================
PCAP_FILE="$PCAPS_BASE_DIR/kwikset-doorlock/wlan1/kwikset-doorlock.wlan1.detection.pcap"

# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/kwikset-doorlock/analyses/kwikset-doorlock-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/kwikset-doorlock/analyses/kwikset-doorlock-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/kwikset-doorlock/signatures/kwikset-doorlock-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/kwikset-doorlock/signatures/kwikset-doorlock-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/kwikset-doorlock/kwikset-doorlock.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="3161"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= NEST THERMOSTAT ====================================================
PCAP_FILE="$PCAPS_BASE_DIR/nest-thermostat/wlan1/nest-thermostat.wlan1.detection.pcap"

# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/nest-thermostat/analyses/nest-thermostat-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/nest-thermostat/analyses/nest-thermostat-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/nest-thermostat/signatures/nest-thermostat-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/nest-thermostat/signatures/nest-thermostat-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/nest-thermostat/nest-thermostat.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="1179"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== RACHIO SPRINKLER QUICK RUN ============================================
PCAP_FILE="$PCAPS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun.wlan1.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/analyses/rachio-sprinkler-quickrun-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/analyses/rachio-sprinkler-quickrun-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/signatures/rachio-sprinkler-quickrun-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/signatures/rachio-sprinkler-quickrun-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/rachio-sprinkler-quickrun.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="2695"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
PCAP_FILE="$PCAPS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun.wlan1.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/analyses/rachio-sprinkler-quickrun-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/analyses/rachio-sprinkler-quickrun-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/signatures/rachio-sprinkler-quickrun-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/signatures/rachio-sprinkler-quickrun-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/rachio-sprinkler-quickrun.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="5490"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
PCAP_FILE="$PCAPS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun.wlan1.ifttt.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/analyses/rachio-sprinkler-quickrun-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/analyses/rachio-sprinkler-quickrun-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/signatures/rachio-sprinkler-quickrun-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/signatures/rachio-sprinkler-quickrun-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/rachio-sprinkler-quickrun.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="5145"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= RACHIO SPRINKLER MODE ==============================================
PCAP_FILE="$PCAPS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/wlan1/rachio-sprinkler-mode.wlan1.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/analyses/rachio-sprinkler-mode-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/analyses/rachio-sprinkler-mode-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/signatures/rachio-sprinkler-mode-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/signatures/rachio-sprinkler-mode-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-mode/rachio-sprinkler-mode.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="2791"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
PCAP_FILE="$PCAPS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/wlan1/rachio-sprinkler-mode.wlan1.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/analyses/rachio-sprinkler-mode-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/analyses/rachio-sprinkler-mode-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/signatures/rachio-sprinkler-mode-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/signatures/rachio-sprinkler-mode-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-mode/rachio-sprinkler-mode.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="2503"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ===================================================== RING ALARM =====================================================
PCAP_FILE="$PCAPS_BASE_DIR/ring-alarm/wlan1/ring-alarm.wlan1.detection.pcap"

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
PCAP_FILE="$PCAPS_BASE_DIR/roomba-vacuum-robot/wlan1/roomba-vacuum-robot.wlan1.detection.pcap"

# PHONE SIDE
ANALYSIS="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/analyses/roomba-vacuum-robot-Clusters-phone-side.cls"
SIGNATURE="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/signatures/roomba-vacuum-robot-Signature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/roomba-vacuum-robot/roomba-vacuum-robot.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="5959"
EPSILON="10.0"
EVENT_TYPES="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/timestamps/roomba-vacuum-robot-apr-25-2019-eventTypes.txt"
EVENTS_OCCURED="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/timestamps/roomba-vacuum-robot-apr-25-2019-eventsOccured.txt"

PROGRAM_ARGS="'$PCAP_FILE' '$ANALYSIS' '$SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$EVENT_TYPES' '$EVENTS_OCCURED'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== SENGLED BULB ON/OFF ==================================================
PCAP_FILE="$PCAPS_BASE_DIR/sengled-bulb/sengled-bulb-onoff/wlan1/sengled-bulb-onoff.wlan1.detection.pcap"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/analyses/sengled-bulb-onoff-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/analyses/sengled-bulb-onoff-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/signatures/sengled-bulb-onoff-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/signatures/sengled-bulb-onoff-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/sengled-bulb/sengled-bulb-onoff/sengled-bulb-onoff.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="10045"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== SENGLED BULB INTENSITY ===============================================
PCAP_FILE="$PCAPS_BASE_DIR/sengled-bulb/sengled-bulb-intensity/wlan1/sengled-bulb-intensity.wlan1.detection.pcap"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/analyses/sengled-bulb-intensity-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/analyses/sengled-bulb-intensity-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/signatures/sengled-bulb-intensity-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/signatures/sengled-bulb-intensity-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/sengled-bulb/sengled-bulb-intensity/sengled-bulb-intensity.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="7888"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ====================================================== ST PLUG =======================================================
PCAP_FILE="$PCAPS_BASE_DIR/st-plug/wlan1/st-plug.wlan1.detection.pcap"

# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/st-plug/analyses/st-plug-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/st-plug/analyses/st-plug-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/st-plug/signatures/st-plug-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/st-plug/signatures/st-plug-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/st-plug/st-plug.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="2445"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= TP LINK BULB ON/OFF ================================================
# LOCAL
PCAP_FILE="$PCAPS_BASE_DIR/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff.wlan1.detection.pcap"

# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/analyses/tplink-bulb-onoff-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/analyses/tplink-bulb-onoff-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/signatures/tplink-bulb-onoff-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/signatures/tplink-bulb-onoff-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/tplink-bulb-onoff.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="162"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
PCAP_FILE="$PCAPS_BASE_DIR/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff.wlan1.ifttt.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/analyses/tplink-bulb-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/analyses/tplink-bulb-onoff-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/signatures/tplink-bulb-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/signatures/tplink-bulb-onoff-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/tplink-bulb-onoff.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="86"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================ TP-LINK BULB COLOR ==================================================
# LOCAL
PCAP_FILE="$PCAPS_BASE_DIR/tplink-bulb/tplink-bulb-color/wlan1/tplink-bulb-color.wlan1.detection.pcap"

# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/analyses/tplink-bulb-color-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/analyses/tplink-bulb-color-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/signatures/tplink-bulb-color-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/signatures/tplink-bulb-color-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/tplink-bulb-color.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="191"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
PCAP_FILE="$PCAPS_BASE_DIR/tplink-bulb/tplink-bulb-color/wlan1/tplink-bulb-color.wlan1.ifttt.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/analyses/tplink-bulb-color-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/analyses/tplink-bulb-color-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/signatures/tplink-bulb-color-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/signatures/tplink-bulb-color-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/tplink-bulb-color.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="66"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== TP-LINK BULB INTENSITY ================================================
# LOCAL
PCAP_FILE="$PCAPS_BASE_DIR/tplink-bulb/tplink-bulb-intensity/wlan1/tplink-bulb-intensity.wlan1.detection.pcap"

# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/analyses/tplink-bulb-intensity-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/analyses/tplink-bulb-intensity-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/signatures/tplink-bulb-intensity-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/signatures/tplink-bulb-intensity-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/tplink-bulb-intensity.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="209"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
PCAP_FILE="$PCAPS_BASE_DIR/tplink-bulb/tplink-bulb-intensity/wlan1/tplink-bulb-intensity.wlan1.ifttt.detection.pcap"

# TODO: The results may look weird but this is just because ON and OFF signatures are actually one feature
# TODO: The result analysis script will show that there is only 1 false negative in total
# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/analyses/tplink-bulb-intensity-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/analyses/tplink-bulb-intensity-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/signatures/tplink-bulb-intensity-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/signatures/tplink-bulb-intensity-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/tplink-bulb-intensity.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="59"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== TP-LINK PLUG ====================================================
PCAP_FILE="$PCAPS_BASE_DIR/tplink-plug/wlan1/tplink-plug.wlan1.detection.pcap"

# DEVICE SIDE (both the 112, 115 and 556, 1293 sequences)
ON_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-plug/analyses/tplink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-plug/analyses/tplink-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-plug/signatures/tplink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-plug/signatures/tplink-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/tplink-plug/tplink-plug.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="3660"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"

# Phone side does not make sense as it is merely a subset of the device side and does not differentiate ONs from OFFs.
# ======================================================================================================================
# TODO: We tested this only for the TP-Link plug on the Mon(IoT)r public dataset
# TODO: Please generate the signatures using the Mon(IoT)r PUBLIC DATASET section in execute_signature_generation.sh
# RELAXED MATCHING
PCAP_FILE="$PCAPS_BASE_DIR/tplink-plug/wlan/tplink-plug.wlan.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-plug/analyses/tplink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-plug/analyses/tplink-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-plug/signatures/tplink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-plug/signatures/tplink-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/tplink-plug/tplink-plug.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="902"
EPSILON="10.0"
MINUS_R="-r"
DELTA="21"
PACKETLIST="592,1234,593,1235"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$MINUS_R' '$DELTA' '$PACKETLIST'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"

# Phone side does not make sense as it is merely a subset of the device side and does not differentiate ONs from OFFs.
# ======================================================================================================================
# REMOTE
PCAP_FILE="$PCAPS_BASE_DIR/tplink-plug/wlan1/tplink-plug.wlan1.detection.pcap"

ON_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-plug/analyses/tplink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-plug/analyses/tplink-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-plug/signatures/tplink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-plug/signatures/tplink-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/tplink-plug/tplink-plug.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="990"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
PCAP_FILE="$PCAPS_BASE_DIR/tplink-plug/wlan1/tplink-plug.wlan1.ifttt.detection.pcap"

ON_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-plug/analyses/tplink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-plug/analyses/tplink-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-plug/signatures/tplink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-plug/signatures/tplink-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/tplink-plug/tplink-plug.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="153"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== WEMO INSIGHT PLUG =================================================
# LOCAL
PCAP_FILE="$PCAPS_BASE_DIR/wemo-insight-plug/wlan1/wemo-insight-plug.wlan1.detection.pcap"

# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/wemo-insight-plug/analyses/wemo-insight-plug-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/wemo-insight-plug/analyses/wemo-insight-plug-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/wemo-insight-plug/signatures/wemo-insight-plug-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/wemo-insight-plug/signatures/wemo-insight-plug-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/wemo-insight-plug/wemo-insight-plug.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="106"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
PCAP_FILE="$PCAPS_BASE_DIR/wemo-insight-plug/wlan1/wemo-insight-plug.wlan1.ifttt.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/wemo-insight-plug/analyses/wemo-insight-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/wemo-insight-plug/analyses/wemo-insight-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/wemo-insight-plug/signatures/wemo-insight-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/wemo-insight-plug/signatures/wemo-insight-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/wemo-insight-plug/wemo-insight-plug.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="521"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ===================================================== WEMO PLUG ======================================================
# LOCAL
PCAP_FILE="$PCAPS_BASE_DIR/wemo-plug/wlan1/wemo-plug.wlan1.detection.pcap"

# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/wemo-plug/analyses/wemo-plug-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/wemo-plug/analyses/wemo-plug-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/wemo-plug/signatures/wemo-plug-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/wemo-plug/signatures/wemo-plug-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/wemo-plug/wemo-plug.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="147"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
PCAP_FILE="$PCAPS_BASE_DIR/wemo-plug/wlan1/wemo-plug.wlan1.ifttt.detection.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/wemo-plug/analyses/wemo-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/wemo-plug/analyses/wemo-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/wemo-plug/signatures/wemo-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/wemo-plug/signatures/wemo-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/wemo-plug/wemo-plug.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="2460"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# TODO: Mon(IoT)r DATASET DEVICES
# ================================================= BLINK CAMERA WATCH =================================================
PCAP_FILE="$PCAPS_BASE_DIR/blink-camera/blink-camera-watch/wlan/blink-camera-watch.wlan.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-watch/analyses/blink-camera-watch-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-watch/analyses/blink-camera-watch-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-watch/signatures/blink-camera-watch-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-watch/signatures/blink-camera-watch-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/blink-camera/blink-camera-watch/blink-camera-watch.wlan.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="365"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= BLINK CAMERA PHOTO =================================================
PCAP_FILE="$PCAPS_BASE_DIR/blink-camera/blink-camera-photo/wlan/blink-camera-photo.wlan.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-photo/analyses/blink-camera-photo-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-photo/analyses/blink-camera-photo-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-photo/signatures/blink-camera-photo-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-photo/signatures/blink-camera-photo-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/blink-camera/blink-camera-photo/blink-camera-photo.wan.detection.pcap___device-side.detectionresults"
# TODO: We had to relax the duration here
#SIGNATURE_DURATION="1429"
SIGNATURE_DURATION="12000"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== WEMO INSIGHT PLUG =================================================
# LOCAL
PCAP_FILE="$PCAPS_BASE_DIR/wemo-insight-plug/wlan/wemo-insight-plug.wlan.pcap"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/wemo-insight-plug/analyses/wemo-insight-plug-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/wemo-insight-plug/analyses/wemo-insight-plug-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/wemo-insight-plug/signatures/wemo-insight-plug-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/wemo-insight-plug/signatures/wemo-insight-plug-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/wemo-insight-plug/wemo-insight-plug.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="124"
EPSILON="10.0"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================
# ================================================= TP LINK BULB ON/OFF ================================================
# LOCAL
PCAP_FILE="$PCAPS_BASE_DIR/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff.wlan1.detection.pcap"

# Has no device side signature.

# PHONE SIDE
ANALYSIS="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/analyses/tplink-bulb-onoff-Clusters-phone-side.cls"
SIGNATURE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/signatures/tplink-bulb-onoff-Signature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/tplink-bulb-onoff.wlan1.detection.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="162"
EPSILON="10.0"

EVENT_TYPES="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-nov-16-2018-eventTypes.txt"
EVENTS_OCCURED="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-nov-16-2018-eventsOccured.txt"
PROGRAM_ARGS="'$PCAP_FILE' '$ANALYSIS' '$SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$EVENT_TYPES' '$EVENTS_OCCURED'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ===================================================== RING ALARM =====================================================
PCAP_FILE="$PCAPS_BASE_DIR/ring-alarm/wlan1/ring-alarm.wlan1.detection.pcap"

# DEVICE SIDE
ANALYSIS="$SIGNATURES_BASE_DIR/ring-alarm/analyses/ring-alarm-Clusters-device-side.cls"
SIGNATURE="$SIGNATURES_BASE_DIR/ring-alarm/signatures/ring-alarm-Signature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/ring-alarm/ring-alarm.wlan1.detection.pcap___device-side.detectionresults"
SIGNATURE_DURATION="665"
EPSILON="10.0"
EVENT_TYPES="$SIGNATURES_BASE_DIR/ring-alarm/timestamps/ring-alarm-apr-26-2019-eventTypes.txt"
EVENTS_OCCURED="$SIGNATURES_BASE_DIR/ring-alarm/timestamps/ring-alarm-apr-26-2019-eventsOccured.txt"

PROGRAM_ARGS="'$PCAP_FILE' '$ANALYSIS' '$SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$EVENT_TYPES' '$EVENTS_OCCURED'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================