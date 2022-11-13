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
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/amazon-plug/timestamps/amazon-plug-apr-16-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/amazon-plug/amazon-plug.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/amazon-plug/timestamps/amazon-plug-dec-6-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/amazon-plug/amazon-plug.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== ARLO CAMERA =====================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/arlo-camera/timestamps/arlo-camera-nov-13-2018.timestamps"
RESULTS_FILE="$RESULTS_BASE_DIR/arlo-camera/arlo-camera.wlan1.validation.pcap___phone-side.detectionresults"
# Put the analysis results in the same folder as the detection results.
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"


PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT - start recording feature
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/arlo-camera/timestamps/arlo-camera-ifttt-dec-15-2019.timestamps"
RESULTS_FILE="$RESULTS_BASE_DIR/arlo-camera/arlo-camera.wlan1.validation.pcap___device-side.detectionresults"
# Put the analysis results in the same folder as the detection results.
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"


PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================= BLOSSOM SPRINKLER QUICK RUN ============================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/timestamps/blossom-sprinkler-quickrun-jan-14-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/blossom-sprinkler-quickrun.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/blossom-sprinkler-quickrun.wlan1.validation.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== BLOSSOM SPRINKLER MODE ===============================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/timestamps/blossom-sprinkler-mode-apr-15-2019.timestamps"

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/blossom-sprinkler-mode.wlan1.validation.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== D-LINK PLUG =====================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/dlink-plug/timestamps/dlink-plug-nov-7-2018.timestamps"

# DEVICE SIDE
# This one is going to generate 97 FPs because every event is counted twice (same signatures for ON and OFF).
RESULTS_FILE="$RESULTS_BASE_DIR/dlink-plug/dlink-plug.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/dlink-plug/dlink-plug.wlan1.validation.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/dlink-plug/timestamps/dlink-plug-dec-2-2019.timestamps"

# DEVICE SIDE
# This one is going to generate 97 FPs because every event is counted twice (same signatures for ON and OFF).
RESULTS_FILE="$RESULTS_BASE_DIR/dlink-plug/dlink-plug.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/dlink-plug/timestamps/dlink-plug-ifttt-dec-11-2019.timestamps"

# DEVICE SIDE
# This one is going to generate 96 FPs because every event is counted twice (same signatures for ON and OFF).
RESULTS_FILE="$RESULTS_BASE_DIR/dlink-plug/dlink-plug.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== D-LINK SIREN ====================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/dlink-siren/timestamps/dlink-siren-nov-9-2018.timestamps"

#PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/dlink-siren/dlink-siren.wlan1.validation.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
# There is only one signature basically for ON (IFTTT doesn't provide a feature for OFF)
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/dlink-siren/timestamps/dlink-siren-ifttt-dec-14-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/dlink-siren/dlink-siren.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== ECOBEE THERMOSTAT HVAC ===============================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/timestamps/ecobee-thermostat-hvac-apr-17-2019.timestamps"

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/ecobee-thermostat-hvac.wlan1.validation.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== ECOBEE THERMOSTAT FAN ================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/timestamps/ecobee-thermostat-fan-apr-18-2019.timestamps"

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/ecobee-thermostat-fan.wlan1.validation.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ======================================================= HUE BULB =====================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/hue-bulb/timestamps/hue-bulb-sept-11-2019.timestamps"

#DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/hue-bulb/hue-bulb.eth1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== HUE BULB ON/OFF ===================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/hue-bulb/hue-bulb-onoff/timestamps/hue-bulb-onoff-ifttt-dec-15-2019.timestamps"

#DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/hue-bulb/hue-bulb-onoff/hue-bulb-onoff.eth1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================ HUE BULB INTENSITY ==================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/hue-bulb/hue-bulb-intensity/timestamps/hue-bulb-intensity-ifttt-dec-20-2019.timestamps"

# TODO: THERE WILL BE 50 FPS BECAUSE EVENTS ARE DETECTED TWICE (ON/OFF SIGNATURES ARE BOTH REFERRING TO THE SAME EVENT)
#DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/hue-bulb/hue-bulb-intensity/hue-bulb-intensity.eth1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= KWIKSET DOORLOCK ===================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/kwikset-doorlock/timestamps/kwikset-doorlock-nov-10-2018.timestamps"

# Has no device side signature.

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/kwikset-doorlock/kwikset-doorlock.wlan1.validation.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= NEST THERMOSTAT ====================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/nest-thermostat/timestamps/nest-thermostat-nov-15-2018.timestamps"

# Has no device side signature.

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/nest-thermostat/nest-thermostat.wlan1.validation.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== RACHIO SPRINKLER QUICK RUN ============================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/timestamps/rachio-sprinkler-quickrun-apr-18-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/rachio-sprinkler-quickrun.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/timestamps/rachio-sprinkler-quickrun-dec-4-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/rachio-sprinkler-quickrun.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/timestamps/rachio-sprinkler-quickrun-ifttt-dec-12-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/rachio-sprinkler-quickrun.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== RACHIO SPRINKLER MODE ================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/timestamps/rachio-sprinkler-mode-apr-18-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/rachio-sprinkler-mode.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/timestamps/rachio-sprinkler-mode-dec-4-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/rachio-sprinkler-mode.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ===================================================== RING ALARM =====================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/ring-alarm/timestamps/ring-alarm-apr-26-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/ring-alarm/ring-alarm.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/ring-alarm/timestamps/ring-alarm-dec-9-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/ring-alarm/ring-alarm.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= ROOMBA VACUUM ROBOT ================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/roomba-vacuum-robot/timestamps/roomba-vacuum-robot-apr-25-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/roomba-vacuum-robot/roomba-vacuum-robot.wlan1.validation.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== SENGLED BULB ON/OFF ==================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/sengled-bulb/sengled-bulb-onoff/timestamps/sengled-bulb-onoff-apr-24-2019.timestamps"

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/sengled-bulb/sengled-bulb-onoff/sengled-bulb-onoff.wlan1.validation.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/sengled-bulb/sengled-bulb-onoff/sengled-bulb-onoff.eth1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== SENGLED BULB INTENSITY ===============================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/sengled-bulb/sengled-bulb-intensity/timestamps/sengled-bulb-intensity-apr-17-2019.timestamps"

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/sengled-bulb/sengled-bulb-intensity/sengled-bulb-intensity.wlan1.validation.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/sengled-bulb/sengled-bulb-intensity/sengled-bulb-intensity.eth1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ====================================================== ST PLUG =======================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/st-plug/timestamps/st-plug-nov-12-2018.timestamps"

# Has no device side signature.

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/st-plug/st-plug.wlan1.validation.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= TP LINK BULB ON/OFF ================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-nov-16-2018.timestamps"

# Has no device side signature.

# PHONE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-bulb/tplink-bulb-onoff/tplink-bulb-onoff.wlan1.validation.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-ifttt-dec-14-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-bulb/tplink-bulb-onoff/tplink-bulb-onoff.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= TP LINK BULB COLOR =================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-bulb/tplink-bulb-color/timestamps/tplink-bulb-color-apr-12-2019.timestamps"

# PHONE SIDE
# This one is going to generate 100 FPs because every event is counted twice (same signatures for ON and OFF).
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-bulb/tplink-bulb-color/tplink-bulb-color.wlan1.validation.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-bulb/tplink-bulb-color/timestamps/tplink-bulb-color-ifttt-dec-18-2019.timestamps"

# PHONE SIDE
# This one is going to generate 100 FPs because every event is counted twice (same signatures for ON and OFF).
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-bulb/tplink-bulb-color/tplink-bulb-color.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# =============================================== TP LINK BULB INTENSITY ===============================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-bulb/tplink-bulb-intensity/timestamps/tplink-bulb-intensity-apr-12-2019.timestamps"

# PHONE SIDE
# This one is going to generate 100 FPs because every event is counted twice (same signatures for ON and OFF).
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-bulb/tplink-bulb-intensity/tplink-bulb-intensity.wlan1.validation.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-bulb/tplink-bulb-intensity/timestamps/tplink-bulb-intensity-ifttt-dec-18-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-bulb/tplink-bulb-intensity/tplink-bulb-intensity.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ==================================================== TP-LINK PLUG ====================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-plug/timestamps/tplink-plug-nov-8-2018.timestamps"
# TODO: Timestamp file for public-dataset PCAP file
#TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-plug/timestamps/tplink-plug-retraining-dec-25-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-plug/tplink-plug.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"

# DEVICE SIDE OUTBOUND
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-plug/tplink-plug.wlan1.validation.pcap___device-side-outbound.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# REMOTE
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-plug/timestamps/tplink-plug-dec-2-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-plug/tplink-plug.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-plug/timestamps/tplink-plug-ifttt-dec-10-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/tplink-plug/tplink-plug.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================== WEMO INSIGHT PLUG =================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/wemo-insight-plug/timestamps/wemo-insight-plug-nov-21-2018.timestamps"
# TODO: Timestamp file for public-dataset PCAP file
#TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/wemo-insight-plug/timestamps/wemo-insight-plug-retraining-jan-9-2020.timestamps"

# Has no device side signature.

# PHONE SIDE
# This one is going to generate 100 FPs because every event is counted twice (same signatures for ON and OFF).
RESULTS_FILE="$RESULTS_BASE_DIR/wemo-insight-plug/wemo-insight-plug.wlan1.validation.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/wemo-insight-plug/timestamps/wemo-insight-plug-ifttt-dec-14-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/wemo-insight-plug/wemo-insight-plug.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ===================================================== WEMO PLUG ======================================================
# LOCAL
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/wemo-plug/timestamps/wemo-plug-nov-20-2018.timestamps"

# Has no device side signature.

# PHONE SIDE
# This one is going to generate 100 FPs because every event is counted twice (same signatures for ON and OFF).
RESULTS_FILE="$RESULTS_BASE_DIR/wemo-plug/wemo-plug.wlan1.validation.pcap___phone-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
# IFTTT
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/wemo-plug/timestamps/wemo-plug-ifttt-dec-16-2019.timestamps"

# DEVICE SIDE
RESULTS_FILE="$RESULTS_BASE_DIR/wemo-plug/wemo-plug.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# TODO: SAME VENDOR OBSERVATION (TP-LINK DEVICES)
# =============================================== TP-LINK TWO-OUTLET PLUG ==============================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-two-outlet-plug/timestamps/tplink-two-outlet-plug-dec-22-2019.timestamps"

RESULTS_FILE="$RESULTS_BASE_DIR/tplink-two-outlet-plug/tplink-two-outlet-plug.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= TP-LINK POWER STRIP ================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-power-strip/timestamps/tplink-power-strip-dec-22-2019.timestamps"

RESULTS_FILE="$RESULTS_BASE_DIR/tplink-power-strip/tplink-power-strip.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================== TP-LINK LIGHT BULB ON/OFF =============================================
# KL-110 (newer model than LB-130 but no color---only dimmable white)
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-bulb-white/tplink-bulb-white-onoff/timestamps/tplink-bulb-white-onoff-dec-21-2019.timestamps"

RESULTS_FILE="$RESULTS_BASE_DIR/tplink-bulb-white/tplink-bulb-white-onoff/tplink-bulb-white-onoff.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ============================================= TP-LINK LIGHT BULB INTENSITY ===========================================
# KL-110 (newer model than LB-130 but no color---only dimmable white)
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-bulb-white/tplink-bulb-white-intensity/timestamps/tplink-bulb-white-intensity-dec-21-2019.timestamps"

RESULTS_FILE="$RESULTS_BASE_DIR/tplink-bulb-white/tplink-bulb-white-intensity/tplink-bulb-white-intensity.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================ TP-LINK CAMERA ON/OFF ===============================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/tplink-camera/tplink-camera-onoff/timestamps/tplink-camera-onoff-dec-22-2019.timestamps"

RESULTS_FILE="$RESULTS_BASE_DIR/tplink-camera/tplink-camera-onoff/tplink-camera-onoff.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# TODO: Mon(IoT)r (NEW DEVICE)
# ================================================= BLINK CAMERA WATCH =================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/blink-camera/blink-camera-watch/timestamps/blink-camera-watch-retraining-dec-23-2019.timestamps"

RESULTS_FILE="$RESULTS_BASE_DIR/blink-camera/blink-camera-watch/blink-camera-watch.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================

# ================================================= BLINK CAMERA PHOTO =================================================
TIMESTAMPS_FILE="$TIMESTAMPS_BASE_DIR/blink-camera/blink-camera-photo/timestamps/blink-camera-photo-retraining-dec-24-2019.timestamps"

RESULTS_FILE="$RESULTS_BASE_DIR/blink-camera/blink-camera-photo/blink-camera-photo.wlan1.validation.pcap___device-side.detectionresults"
ANALYSIS_RESULTS_FILE="$RESULTS_FILE.analysis"
EXACT_MATCH="true"
PROGRAM_ARGS="'$TIMESTAMPS_FILE' '$RESULTS_FILE' '$ANALYSIS_RESULTS_FILE' '$EXACT_MATCH'"
#./gradlew run -DmainClass=edu.uci.iotproject.evaluation.DetectionResultsAnalyzer --args="$PROGRAM_ARGS"
# ======================================================================================================================
