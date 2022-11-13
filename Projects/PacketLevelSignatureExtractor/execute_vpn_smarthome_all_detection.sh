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

VPNCMD="-vpn"

# ==================================================== AMAZON PLUG =====================================================
PCAP_FILE="$PCAPS_BASE_DIR/amazon-plug/vpn/amazon-plug.eth1.stpvpn.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/amazon-plug/analyses/amazon-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/amazon-plug/analyses/amazon-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/amazon-plug/signatures/amazon-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/amazon-plug/signatures/amazon-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/amazon-plug/amazon-plug.eth1.stpvpn.pcap___device-side.detectionresults"
SIGNATURE_DURATION="4990"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== ARLO CAMERA =====================================================
PCAP_FILE="$PCAPS_BASE_DIR/arlo-camera/vpn/arlo-camera.eth1.stpvpn.pcap"

# Has no device side signature.

# PHONE SIDE (TODO: may possibly be the .incomplete signatures)
ON_ANALYSIS="$SIGNATURES_BASE_DIR/arlo-camera/analyses/arlo-camera-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/arlo-camera/analyses/arlo-camera-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/arlo-camera/signatures/arlo-camera-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/arlo-camera/signatures/arlo-camera-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/arlo-camera/arlo-camera.eth1.stpvpn.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="548"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================= BLOSSOM SPRINKLER QUICK RUN ============================================
PCAP_FILE="$PCAPS_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/vpn/blossom-sprinkler-quickrun.eth1.stpvpn.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/analyses/blossom-sprinkler-quickrun-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/analyses/blossom-sprinkler-quickrun-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/signatures/blossom-sprinkler-quickrun-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/signatures/blossom-sprinkler-quickrun-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/blossom-sprinkler-quickrun.eth1.stpvpn.pcap___device-side.detectionresults"
SIGNATURE_DURATION="9274"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/analyses/blossom-sprinkler-quickrun-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/analyses/blossom-sprinkler-quickrun-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/signatures/blossom-sprinkler-quickrun-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/signatures/blossom-sprinkler-quickrun-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/blossom-sprinkler-quickrun.eth1.stpvpn.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="3670"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== BLOSSOM SPRINKLER MODE ================================================
PCAP_FILE="$PCAPS_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/vpn/blossom-sprinkler-mode.eth1.stpvpn.pcap"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/analyses/blossom-sprinkler-mode-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/analyses/blossom-sprinkler-mode-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/signatures/blossom-sprinkler-mode-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/signatures/blossom-sprinkler-mode-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-mode/blossom-sprinkler-mode.eth1.stpvpn.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="1977"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== D-LINK PLUG =====================================================
PCAP_FILE="$PCAPS_BASE_DIR/dlink-plug/vpn/dlink-plug.eth1.stpvpn.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-plug/analyses/dlink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-plug/analyses/dlink-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-plug/signatures/dlink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-plug/signatures/dlink-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/dlink-plug/dlink-plug.eth1.stpvpn.pcap___device-side.detectionresults"
SIGNATURE_DURATION="8866"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-plug/analyses/dlink-plug-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-plug/analyses/dlink-plug-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-plug/signatures/dlink-plug-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-plug/signatures/dlink-plug-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/dlink-plug/dlink-plug.eth1.stpvpn.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="193"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== D-LINK SIREN ====================================================
PCAP_FILE="$PCAPS_BASE_DIR/dlink-siren/vpn/dlink-siren.eth1.stpvpn.pcap"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-siren/analyses/dlink-siren-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/dlink-siren/analyses/dlink-siren-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-siren/signatures/dlink-siren-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/dlink-siren/signatures/dlink-siren-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/dlink-siren/dlink-siren.eth1.stpvpn.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="71"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== ECOBEE THERMOSTAT HVAC ===============================================
PCAP_FILE="$PCAPS_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/vpn/ecobee-thermostat-hvac.eth1.stpvpn.pcap"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/analyses/ecobee-thermostat-hvac-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/analyses/ecobee-thermostat-hvac-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/signatures/ecobee-thermostat-hvac-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/signatures/ecobee-thermostat-hvac-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-hvac/ecobee-thermostat-hvac.eth1.stpvpn.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="733"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"

# ======================================================================================================================

# =============================================== ECOBEE THERMOSTAT FAN ================================================
PCAP_FILE="$PCAPS_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/vpn/ecobee-thermostat-fan.eth1.stpvpn.pcap"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/analyses/ecobee-thermostat-fan-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/analyses/ecobee-thermostat-fan-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/signatures/ecobee-thermostat-fan-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/signatures/ecobee-thermostat-fan-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-fan/ecobee-thermostat-fan.eth1.stpvpn.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="1953"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"

# ======================================================================================================================

# ================================================= KWIKSET DOORLOCK ===================================================
PCAP_FILE="$PCAPS_BASE_DIR/kwikset-doorlock/vpn/kwikset-doorlock.eth1.stpvpn.pcap"

# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/kwikset-doorlock/analyses/kwikset-doorlock-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/kwikset-doorlock/analyses/kwikset-doorlock-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/kwikset-doorlock/signatures/kwikset-doorlock-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/kwikset-doorlock/signatures/kwikset-doorlock-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/kwikset-doorlock/kwikset-doorlock.eth1.stpvpn.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="3161"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= NEST THERMOSTAT ====================================================
PCAP_FILE="$PCAPS_BASE_DIR/nest-thermostat/vpn/nest-thermostat.eth1.stpvpn.pcap"

# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/nest-thermostat/analyses/nest-thermostat-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/nest-thermostat/analyses/nest-thermostat-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/nest-thermostat/signatures/nest-thermostat-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/nest-thermostat/signatures/nest-thermostat-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/nest-thermostat/nest-thermostat.eth1.stpvpn.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="1179"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== RACHIO SPRINKLER QUICK RUN ============================================
PCAP_FILE="$PCAPS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/vpn/rachio-sprinkler-quickrun.eth1.stpvpn.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/analyses/rachio-sprinkler-quickrun-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/analyses/rachio-sprinkler-quickrun-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/signatures/rachio-sprinkler-quickrun-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/signatures/rachio-sprinkler-quickrun-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/rachio-sprinkler-quickrun.eth1.stpvpn.pcap___device-side.detectionresults"
SIGNATURE_DURATION="2695"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= RACHIO SPRINKLER MODE ==============================================
PCAP_FILE="$PCAPS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/vpn/rachio-sprinkler-mode.eth1.stpvpn.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/analyses/rachio-sprinkler-mode-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/analyses/rachio-sprinkler-mode-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/signatures/rachio-sprinkler-mode-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/signatures/rachio-sprinkler-mode-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-mode/rachio-sprinkler-mode.eth1.stpvpn.pcap___device-side.detectionresults"
SIGNATURE_DURATION="2791"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ===================================================== RING ALARM =====================================================
PCAP_FILE="$PCAPS_BASE_DIR/ring-alarm/vpn/ring-alarm.eth1.stpvpn.pcap"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/ring-alarm/analyses/ring-alarm-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/ring-alarm/analyses/ring-alarm-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/ring-alarm/signatures/ring-alarm-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/ring-alarm/signatures/ring-alarm-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/ring-alarm/ring-alarm.eth1.stpvpn.pcap___device-side.detectionresults"
SIGNATURE_DURATION="665"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= ROOMBA VACUUM ROBOT ================================================
PCAP_FILE="$PCAPS_BASE_DIR/roomba-vacuum-robot/vpn/roomba-vacuum-robot.eth1.stpvpn.pcap"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/analyses/roomba-vacuum-robot-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/analyses/roomba-vacuum-robot-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/signatures/roomba-vacuum-robot-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/signatures/roomba-vacuum-robot-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/roomba-vacuum-robot/roomba-vacuum-robot.eth1.stpvpn.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="5959"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== SENGLED BULB ON/OFF ==================================================
PCAP_FILE="$PCAPS_BASE_DIR/sengled-bulb/sengled-bulb-onoff/vpn/sengled-bulb-onoff.eth1.stpvpn.pcap"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/analyses/sengled-bulb-onoff-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/analyses/sengled-bulb-onoff-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/signatures/sengled-bulb-onoff-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/signatures/sengled-bulb-onoff-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/sengled-bulb/sengled-bulb-onoff/sengled-bulb-onoff.eth1.stpvpn.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="10045"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"

# DEVICE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/analyses/sengled-bulb-onoff-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/analyses/sengled-bulb-onoff-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/signatures/sengled-bulb-onoff-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/signatures/sengled-bulb-onoff-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/sengled-bulb/sengled-bulb-onoff/sengled-bulb-onoff.eth1.stpvpn.pcap___device-side.detectionresults"
SIGNATURE_DURATION="8959"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== SENGLED BULB INTENSITY ===============================================
PCAP_FILE="$PCAPS_BASE_DIR/sengled-bulb/sengled-bulb-intensity/vpn/sengled-bulb-intensity.eth1.stpvpn.pcap"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/analyses/sengled-bulb-intensity-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/analyses/sengled-bulb-intensity-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/signatures/sengled-bulb-intensity-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/signatures/sengled-bulb-intensity-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/sengled-bulb/sengled-bulb-intensity/sengled-bulb-intensity.eth1.stpvpn.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="7888"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/analyses/sengled-bulb-intensity-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/analyses/sengled-bulb-intensity-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/signatures/sengled-bulb-intensity-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/signatures/sengled-bulb-intensity-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/sengled-bulb/sengled-bulb-intensity/sengled-bulb-intensity.eth1.stpvpn.pcap___device-side.detectionresults"
SIGNATURE_DURATION="906"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ====================================================== ST PLUG =======================================================
PCAP_FILE="$PCAPS_BASE_DIR/st-plug/vpn/st-plug.eth1.stpvpn.pcap"

# Has no device side signature.

# PHONE SIDE
ON_ANALYSIS="$SIGNATURES_BASE_DIR/st-plug/analyses/st-plug-onClusters-phone-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/st-plug/analyses/st-plug-offClusters-phone-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/st-plug/signatures/st-plug-onSignature-phone-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/st-plug/signatures/st-plug-offSignature-phone-side.sig"
RESULTS_FILE="$OUTPUT_DIR/st-plug/st-plug.eth1.stpvpn.pcap___phone-side.detectionresults"
SIGNATURE_DURATION="2445"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== TP-LINK PLUG ====================================================
PCAP_FILE="$PCAPS_BASE_DIR/tplink-plug/vpn/tplink-plug.eth1.stpvpn.pcap"

# DEVICE SIDE OUTBOUND (contains only those packets that go through the WAN port, i.e., only the 556, 1293 sequence)
ON_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-plug/analyses/tplink-plug-onClusters-device-side.cls"
OFF_ANALYSIS="$SIGNATURES_BASE_DIR/tplink-plug/analyses/tplink-plug-offClusters-device-side.cls"
ON_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-plug/signatures/tplink-plug-onSignature-device-side.sig"
OFF_SIGNATURE="$SIGNATURES_BASE_DIR/tplink-plug/signatures/tplink-plug-offSignature-device-side.sig"
RESULTS_FILE="$OUTPUT_DIR/tplink-plug/tplink-plug.eth1.stpvpn.pcap___device-side-outbound.detectionresults"
SIGNATURE_DURATION="224"
EPSILON="10.0"
ON_SKIPPED_PACKETS="-1"
OFF_SKIPPED_PACKETS="-1"
VPN="b0:b9:8a:73:69:8f"

PROGRAM_ARGS="'$PCAP_FILE' '$ON_ANALYSIS' '$OFF_ANALYSIS' '$ON_SIGNATURE' '$OFF_SIGNATURE' '$RESULTS_FILE' '$SIGNATURE_DURATION' '$EPSILON' '$ON_SKIPPED_PACKETS' '$OFF_SKIPPED_PACKETS' '$VPNCMD' '$VPN'"
#./gradlew run -DmainClass=edu.uci.iotproject.detection.layer2.Layer2SignatureDetector --args="$PROGRAM_ARGS"

# Phone side does not make sense as it is merely a subset of the device side and does not differentiate ONs from OFFs.
# ======================================================================================================================
