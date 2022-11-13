#!/bin/bash

# Base directory where the smarthome evaluation traces and timestamp files are stored,
# (i.e., /some/arbitrary/local/path/experimental_result/smarthome)
TIMESTAMPS_BASE_DIR=$1
readonly TIMESTAMPS_BASE_DIR

# Base directory for the detection results files for the smarthome experiment
RESULTS_BASE_DIR=$2
readonly RESULTS_BASE_DIR

# ==================================================== AMAZON PLUG =====================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/amazon-plug/timestamps/amazon-plug-smarthome-apr-23-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/amazon-plug/amazon-plug.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/amazon-plug/timestamps/amazon-plug-smarthome-dec-6-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/amazon-plug/amazon-plug.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== ARLO CAMERA =====================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/arlo-camera/timestamps/arlo-camera-smarthome-nov-15-2018.timestamps"
RESULTS_FILE="$RESULTS_BASE_DIR/arlo-camera/arlo-camera.eth0.detection.pcap___phone-side.detectionresults"
# Put the analysis results in the same folder as the detection results.
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"

PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
# We will see 100 FPs because we have the same signature (this is only one type of event)
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/arlo-camera/timestamps/arlo-camera-smarthome-ifttt-dec-16-2019.timestamps"
RESULTS_FILE="$RESULTS_BASE_DIR/arlo-camera/arlo-camera.eth0.detection.pcap___device-side.detectionresults"
# Put the analysis results in the same folder as the detection results.
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"

PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================= BLOSSOM SPRINKLER QUICK RUN ============================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/timestamps/blossom-sprinkler-quickrun-smarthome-jan-14-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/blossom-sprinkler-quickrun.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/blossom-sprinkler-quickrun.eth0.detection.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== BLOSSOM SPRINKLER MODE ================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/timestamps/blossom-sprinkler-mode-smarthome-apr-22-2019.timestamps"

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/blossom-sprinkler-mode.eth0.detection.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== D-LINK PLUG =====================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/dlink-plug/timestamps/dlink-plug-smarthome-nov-8-2018.timestamps"

# DEVICE SIDE
# This one is going to generate 95 FPs because every event is counted twice (same signatures for ON and OFF).
RESULTS_FILE="$RESULTS_BASE_DIR/dlink-plug/dlink-plug.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/dlink-plug/dlink-plug.eth0.detection.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/dlink-plug/timestamps/dlink-plug-smarthome-dec-3-2019.timestamps"

# DEVICE SIDE
# This one is going to generate 94 FPs because every event is counted twice (same signatures for ON and OFF).
RESULTS_FILE="$RESULTS_BASE_DIR/dlink-plug/dlink-plug.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/dlink-plug/timestamps/dlink-plug-ifttt-smarthome-dec-12-2019.timestamps"

# DEVICE SIDE
# This one is going to generate 94 FPs because every event is counted twice (same signatures for ON and OFF).
RESULTS_FILE="$RESULTS_BASE_DIR/dlink-plug/dlink-plug.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== D-LINK SIREN ====================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/dlink-siren/timestamps/dlink-siren-smarthome-nov-10-2018.timestamps"

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/dlink-siren/dlink-siren.eth0.detection.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/dlink-siren/timestamps/dlink-siren-ifttt-smarthome-dec-19-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/dlink-siren/dlink-siren.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== ECOBEE THERMOSTAT HVAC ===============================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/timestamps/ecobee-thermostat-hvac-smarthome-apr-24-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/ecobee-thermostat-hvac.eth0.detection.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== ECOBEE THERMOSTAT FAN ================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/timestamps/ecobee-thermostat-fan-smarthome-apr-24-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/ecobee-thermostat-fan.eth0.detection.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== HUE BULB ON/OFF ===================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/hue-bulb/hue-bulb-onoff/timestamps/hue-bulb-onoff-ifttt-smarthome-dec-20-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/hue-bulb/hue-bulb-onoff/hue-bulb-onoff.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================ HUE BULB INTENSITY ==================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/hue-bulb/hue-bulb-intensity/timestamps/hue-bulb-intensity-ifttt-smarthome-dec-20-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/hue-bulb/hue-bulb-intensity/hue-bulb-intensity.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= KWIKSET DOORLOCK ===================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/kwikset-doorlock/timestamps/kwikset-doorlock-smarthome-nov-10-2018.timestamps"

# Has no device side signature.

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/kwikset-doorlock/kwikset-doorlock.eth0.detection.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= NEST THERMOSTAT ====================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/nest-thermostat/timestamps/nest-thermostat-smarthome-nov-16-2018.timestamps"

# Has no device side signature.

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/nest-thermostat/nest-thermostat.eth0.detection.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== RACHIO SPRINKLER QUICK RUN ============================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/timestamps/rachio-sprinkler-quickrun-smarthome-apr-25-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/rachio-sprinkler-quickrun.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/timestamps/rachio-sprinkler-quickrun-smarthome-dec-4-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/rachio-sprinkler-quickrun.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/timestamps/rachio-sprinkler-quickrun-ifttt-smarthome-dec-13-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/rachio-sprinkler-quickrun.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= RACHIO SPRINKLER MODE ==============================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/timestamps/rachio-sprinkler-mode-smarthome-apr-25-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/rachio-sprinkler-mode.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/timestamps/rachio-sprinkler-mode-smarthome-dec-5-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/rachio-sprinkler-mode.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ===================================================== RING ALARM =====================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/ring-alarm/timestamps/ring-alarm-smarthome-apr-26-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/ring-alarm/ring-alarm.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/ring-alarm/timestamps/ring-alarm-smarthome-dec-9-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/ring-alarm/ring-alarm.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= ROOMBA VACUUM ROBOT ================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/roomba-vacuum-robot/timestamps/roomba-vacuum-robot-smarthome-apr-27-2019.timestamps"

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/roomba-vacuum-robot/roomba-vacuum-robot.eth0.detection.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== SENGLED BULB ON/OFF ==================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/sengled-bulb/sengled-bulb-onoff/timestamps/sengled-bulb-onoff-smarthome-apr-23-2019.timestamps"

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/sengled-bulb/sengled-bulb-onoff/sengled-bulb-onoff.eth0.detection.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/sengled-bulb/sengled-bulb-onoff/sengled-bulb-onoff.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== SENGLED BULB INTENSITY ===============================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/sengled-bulb/sengled-bulb-intensity/timestamps/sengled-bulb-intensity-smarthome-apr-24-2019.timestamps"

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/sengled-bulb/sengled-bulb-intensity/sengled-bulb-intensity.eth0.detection.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/sengled-bulb/sengled-bulb-intensity/sengled-bulb-intensity.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ====================================================== ST PLUG =======================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/st-plug/timestamps/st-plug-smarthome-nov-13-2018.timestamps"

# Has no device side signature.

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/st-plug/st-plug.eth0.detection.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= TP LINK BULB ON/OFF ================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-smarthome-nov-19-2018.timestamps"

# Has no device side signature.

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-bulb/tplink-bulb-onoff/tplink-bulb-onoff.wlan1.wan-detection.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-ifttt-smarthome-dec-17-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-bulb/tplink-bulb-onoff/tplink-bulb-onoff.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================ TP-LINK BULB COLOR ==================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-bulb/tplink-bulb-color/timestamps/tplink-bulb-color-smarthome-apr-22-2019.timestamps"

# PHONE SIDE
# This one is going to generate >100 FPs because every event is counted twice (same signatures for ON and OFF).
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-bulb/tplink-bulb-color/tplink-bulb-color.wlan1.wan-detection.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-bulb/tplink-bulb-color/timestamps/tplink-bulb-color-ifttt-smarthome-dec-19-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-bulb/tplink-bulb-color/tplink-bulb-color.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== TP-LINK BULB INTENSITY ================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-bulb/tplink-bulb-intensity/timestamps/tplink-bulb-intensity-smarthome-apr-29-2019.timestamps"

# PHONE SIDE
# This one is going to generate >100 FPs because every event is counted twice (same signatures for ON and OFF).
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-bulb/tplink-bulb-intensity/tplink-bulb-intensity.wlan1.wan-detection.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-bulb/tplink-bulb-intensity/timestamps/tplink-bulb-intensity-ifttt-smarthome-dec-18-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-bulb/tplink-bulb-intensity/tplink-bulb-intensity.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== TP-LINK PLUG ====================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-plug/timestamps/tplink-plug-smarthome-nov-9-2018.timestamps"
# TODO: Timestamp for relaxed matching
#TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-plug/timestamps/tplink-plug.wan.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-plug/tplink-plug.wlan1.wan-detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"

# DEVICE SIDE OUTBOUND
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-plug/tplink-plug.eth0.detection.pcap___device-side-outbound.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="false"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-plug/timestamps/tplink-plug-smarthome-dec-3-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-plug/tplink-plug.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-plug/timestamps/tplink-plug-ifttt-smarthome-dec-11-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-plug/tplink-plug.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== WEMO INSIGHT PLUG =================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/wemo-insight-plug/timestamps/wemo-insight-plug-smarthome-nov-22-2018.timestamps"

# Has no device side signature.

# PHONE SIDE
# This one is going to generate >100 FPs because every event is counted twice (same signatures for ON and OFF).
RESULTS_FILE="$RESULTS_BASE_DIR/wemo-insight-plug/wemo-insight-plug.wlan1.wan-detection.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/wemo-insight-plug/timestamps/wemo-insight-plug-ifttt-smarthome-dec-19-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/wemo-insight-plug/wemo-insight-plug.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ===================================================== WEMO PLUG ======================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/wemo-plug/timestamps/wemo-plug-smarthome-nov-21-2018.timestamps"

# Has no device side signature.

# PHONE SIDE
# This one is going to generate >100 FPs because every event is counted twice (same signatures for ON and OFF).
RESULTS_FILE="$RESULTS_BASE_DIR/wemo-plug/wemo-plug.wlan1.wan-detection.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/wemo-plug/timestamps/wemo-plug-ifttt-smarthome-dec-17-2019.timestamps"

# DEVICE SIDE
# This one is going to generate >100 FPs because every event is counted twice (same signatures for ON and OFF).
RESULTS_FILE="$RESULTS_BASE_DIR/wemo-plug/wemo-plug.eth0.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# TODO: Mon(IoT)r DATASET DEVICES
# TODO: THE LABELS IN THE Mon(IoT)r DATASET ARE NOT STRICTLY 15 SECONDS SO WE HAVE TO LOOSEN THE TIMING CONSTRAINT (30 SECONDS)
# ================================================= BLINK CAMERA WATCH =================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/blink-camera/blink-camera-watch/timestamps/blink-camera-watch.wan.timestamps"

RESULTS_FILE="$RESULTS_BASE_DIR/blink-camera/blink-camera-watch/blink-camera-watch.wan.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= BLINK CAMERA PHOTO =================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/blink-camera/blink-camera-photo/timestamps/blink-camera-photo.wan.timestamps"

RESULTS_FILE="$RESULTS_BASE_DIR/blink-camera/blink-camera-photo/blink-camera-photo.wan.detection.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================