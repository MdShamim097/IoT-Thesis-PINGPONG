#!/bin/bash
#./time-vs-packet-num.sh ip_address timestamp_file pcap_file timezone output_file
hi=0
ip_address=$1
timestamp_file=$2
pcap_file=$3
shell=packet-counter.sh
timezone=$4
output_file=$5
getMax()
{
    touch "$shell"
    chmod +x "$shell"
    python3 tshark-shell-generator.py $3 $2 $1 $shell $4
    hi=0
    for cnt in `./$shell`
    do
        if [ $cnt -gt $hi ]; then
            hi=$cnt
        fi
        echo $cnt
    done
    echo "Maximum: $hi"
    rm "$shell"
}

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

TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/amazon-plug/timestamps/amazon-plug-apr-16-2019.timestamps"
DEVICE_IP="192.168.1.189"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"

#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================
# REMOTE
INPUT_PCAP="$SIGNATURES_BASE_DIR/amazon-plug/wlan1/amazon-plug.wlan1.remote.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/amazon-plug/wlan1/amazon-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/amazon-plug/timestamps/amazon-plug-dec-6-2019.timestamps"
DEVICE_IP="192.168.1.189"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ==================================================== ARLO CAMERA =====================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/arlo-camera/wlan1/arlo-camera.wlan1.local.pcap"

# Has no device side signature.
# PHONE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/arlo-camera/wlan1/arlo-camera-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/arlo-camera/timestamps/arlo-camera-nov-13-2018.timestamps"
DEVICE_IP="192.168.1.246"
TIMEZONE="-8"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================
# IFTTT - start recording feature
INPUT_PCAP="$SIGNATURES_BASE_DIR/arlo-camera/arlo-camera-startrecording/wlan1/arlo-camera-startrecording.wlan1.ifttt.pcap"

# DEVICE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/arlo-camera/arlo-camera-startrecording/wlan1/arlo-camera-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/arlo-camera/arlo-camera-startrecording/timestamps/arlo-camera-startrecording-ifttt-dec-15-2019.timestamps"
DEVICE_IP="192.168.1.142"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ============================================= BLOSSOM SPRINKLER QUICK RUN ============================================
# DEVICE SIDE
INPUT_PCAP="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/wlan1/blossom-sprinkler-quickrun.wlan1.local.pcap"
OUTPUT_PCAP="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/wlan1/blossom-sprinkler-quickrun-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-quickrun/timestamps/blossom-sprinkler-quickrun-jan-14-2019.timestamps"
DEVICE_IP="192.168.1.229"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE

# PHONE SIDE
DEVICE_IP="192.168.1.246"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# =============================================== BLOSSOM SPRINKLER MODE ===============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/wlan1/blossom-sprinkler-mode.wlan1.local.pcap"

# PHONE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/blossom-sprinkler/blossom-sprinkler-mode/wlan1/blossom-sprinkler-mode-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/blossom-sprinkler/blossom-sprinkler-mode/timestamps/blossom-sprinkler-mode-apr-15-2019.timestamps"
DEVICE_IP="192.168.1.246"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE

# DEVICE SIDE
# TODO: For some reason there is no OFF signature for the device side, so we do not report it for now
DEVICE_IP="192.168.1.229"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ==================================================== D-LINK PLUG =====================================================
# LOCAL
# DEVICE SIDE
INPUT_PCAP="$SIGNATURES_BASE_DIR/dlink-plug/wlan1/dlink-plug.wlan1.local.pcap"
OUTPUT_PCAP="$OUTPUT_DIR/dlink-plug/wlan1/dlink-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/dlink-plug/timestamps/dlink-plug-nov-7-2018.timestamps"
DEVICE_IP="192.168.1.199"
TIMEZONE="-8"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE

# PHONE SIDE
DEVICE_IP="192.168.1.246"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================
# REMOTE
# DEVICE SIDE
INPUT_PCAP="$SIGNATURES_BASE_DIR/dlink-plug/wlan1/dlink-plug.wlan1.remote.pcap"
OUTPUT_PCAP="$OUTPUT_DIR/dlink-plug/wlan1/dlink-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/dlink-plug/timestamps/dlink-plug-dec-2-2019.timestamps"
DEVICE_IP="192.168.1.199"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================
# IFTTT
# DEVICE SIDE
INPUT_PCAP="$SIGNATURES_BASE_DIR/dlink-plug/wlan1/dlink-plug.wlan1.ifttt.pcap"
OUTPUT_PCAP="$OUTPUT_DIR/dlink-plug/wlan1/dlink-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/dlink-plug/timestamps/dlink-plug-ifttt-dec-11-2019.timestamps"
DEVICE_IP="192.168.1.199"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ==================================================== D-LINK SIREN ====================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/dlink-siren/wlan1/dlink-siren.wlan1.local.pcap"

# Has no device side signature.
# PHONE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/dlink-siren/wlan1/dlink-siren-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/dlink-siren/timestamps/dlink-siren-nov-9-2018.timestamps"
DEVICE_IP="192.168.1.246"
TIMEZONE="-8"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/dlink-siren/wlan1/dlink-siren.wlan1.ifttt.pcap"

# Has no device side signature.
# DEVICE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/dlink-siren/wlan1/dlink-siren-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/dlink-siren/timestamps/dlink-siren-ifttt-dec-14-2019.timestamps"
DEVICE_IP="192.168.1.184"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# =============================================== ECOBEE THERMOSTAT HVAC ===============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/wlan1/ecobee-thermostat-hvac.wlan1.local.pcap"

# Phone Signature
OUTPUT_PCAP="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-hvac/wlan1/ecobee-thermostat-hvac-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-hvac/timestamps/ecobee-thermostat-hvac-apr-17-2019.timestamps"
DEVICE_IP="192.168.1.130"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# =============================================== ECOBEE THERMOSTAT FAN ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/wlan1/ecobee-thermostat-fan.wlan1.local.pcap"

# Phone Signature
OUTPUT_PCAP="$OUTPUT_DIR/ecobee-thermostat/ecobee-thermostat-fan/wlan1/ecobee-thermostat-fan-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/ecobee-thermostat/ecobee-thermostat-fan/timestamps/ecobee-thermostat-fan-apr-18-2019.timestamps"
DEVICE_IP="192.168.1.130"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ======================================================= HUE BULB =====================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/hue-bulb/eth1/hue-bulb.eth1.local.pcap"

# DEVICE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/hue-bulb/eth1/hue-bulb-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/hue-bulb/timestamps/hue-bulb-sept-11-2019.timestamps"
DEVICE_IP="192.168.1.100"
TIMEZONE="-8"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ================================================== HUE BULB ON/OFF ===================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-onoff/eth1/hue-bulb-onoff.eth1.ifttt.pcap"

# DEVICE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/hue-bulb/hue-bulb-onoff/eth1/hue-bulb-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/hue-bulb/hue-bulb-onoff/timestamps/hue-bulb-onoff-ifttt-dec-15-2019.timestamps"
DEVICE_IP="192.168.1.101"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
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
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ================================================= KWIKSET DOORLOCK ===================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/kwikset-doorlock/wlan1/kwikset-doorlock.wlan1.local.pcap"

# Has no device side signature.
# PHONE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/kwikset-doorlock/wlan1/kwikset-doorlock-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/kwikset-doorlock/timestamps/kwikset-doorlock-nov-10-2018.timestamps"
DEVICE_IP="192.168.1.246"
TIMEZONE="-8"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ================================================= NEST THERMOSTAT ====================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/nest-thermostat/wlan1/nest-thermostat.wlan1.local.pcap"

# Has no device side signature.
# PHONE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/nest-thermostat/wlan1/nest-thermostat-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/nest-thermostat/timestamps/nest-thermostat-nov-15-2018.timestamps"
DEVICE_IP="192.168.1.246"
TIMEZONE="-8"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ============================================== RACHIO SPRINKLER QUICK RUN ============================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun.wlan1.local.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/timestamps/rachio-sprinkler-quickrun-apr-18-2019.timestamps"
DEVICE_IP="192.168.1.143"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================
# REMOTE
INPUT_PCAP="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun.wlan1.remote.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/timestamps/rachio-sprinkler-quickrun-dec-4-2019.timestamps"
DEVICE_IP="192.168.1.143"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun.wlan1.ifttt.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-quickrun/timestamps/rachio-sprinkler-quickrun-ifttt-dec-12-2019.timestamps"
DEVICE_IP="192.168.1.144"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ================================================= RACHIO SPRINKLER MODE ==============================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/wlan1/rachio-sprinkler-mode.wlan1.local.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-mode/wlan1/rachio-sprinkler-mode-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/timestamps/rachio-sprinkler-mode-apr-18-2019.timestamps"
DEVICE_IP="192.168.1.143"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================
# REMOTE
INPUT_PCAP="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/wlan1/rachio-sprinkler-mode.wlan1.remote.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/rachio-sprinkler/rachio-sprinkler-mode/wlan1/rachio-sprinkler-mode-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/rachio-sprinkler/rachio-sprinkler-mode/timestamps/rachio-sprinkler-mode-dec-4-2019.timestamps"
DEVICE_IP="192.168.1.143"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ===================================================== RING ALARM =====================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/ring-alarm/wlan1/ring-alarm.wlan1.local.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/ring-alarm/wlan1/alarm-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/ring-alarm/timestamps/ring-alarm-apr-26-2019.timestamps"
DEVICE_IP="192.168.1.113"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================
# REMOTE
INPUT_PCAP="$SIGNATURES_BASE_DIR/ring-alarm/wlan1/ring-alarm.wlan1.remote.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/ring-alarm/wlan1/alarm-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/ring-alarm/timestamps/ring-alarm-dec-9-2019.timestamps"
DEVICE_IP="192.168.1.113"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ================================================= ROOMBA VACUUM ROBOT ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/wlan1/roomba-vacuum-robot.wlan1.local.pcap"

# Device Signature
OUTPUT_PCAP="$OUTPUT_DIR/roomba-vacuum-robot/wlan1/roomba-vacuum-robot-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/roomba-vacuum-robot/timestamps/roomba-vacuum-robot-apr-25-2019.timestamps"
DEVICE_IP="192.168.1.246"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# =============================================== SENGLED BULB ON/OFF ==================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/wlan1/sengled-bulb-onoff.wlan1.local.pcap"

# Phone Signature
OUTPUT_PCAP="$OUTPUT_DIR/sengled-bulb/sengled-bulb-onoff/wlan1/sengled-bulb-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/timestamps/sengled-bulb-onoff-apr-24-2019.timestamps"
DEVICE_IP="192.168.1.246"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE

# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-onoff/eth1/sengled-bulb-onoff.eth1.local.pcap"

# Device Signature
DEVICE_IP="192.168.1.201"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# =============================================== SENGLED BULB INTENSITY ===============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/wlan1/sengled-bulb-intensity.wlan1.local.pcap"

# Phone Signature
OUTPUT_PCAP="$OUTPUT_DIR/sengled-bulb/sengled-bulb-intensity/wlan1/sengled-bulb-intensity-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/timestamps/sengled-bulb-intensity-apr-17-2019.timestamps"
DEVICE_IP="192.168.1.246"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE

# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/sengled-bulb/sengled-bulb-intensity/eth1/sengled-bulb-intensity.eth1.local.pcap"

# Device Signature
DEVICE_IP="192.168.1.201"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ====================================================== ST PLUG =======================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/st-plug/wlan1/st-plug.wlan1.local.pcap"

# Has no device side signature.
# PHONE SIDE
OUTPUT_PCAP="$OUTPUT_DIR/st-plug/wlan1/st-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/st-plug/timestamps/st-plug-nov-12-2018.timestamps"
DEVICE_IP="192.168.1.246"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ================================================= TP LINK BULB ON/OFF ================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff.wlan1.local.pcap"

# Has LAN signature.
OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-nov-16-2018.timestamps"
DEVICE_IP="192.168.1.246"
TIMEZONE="-8"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"

#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff.wlan1.ifttt.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-ifttt-dec-14-2019.timestamps"
DEVICE_IP="192.168.1.141"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ================================================= TP LINK BULB COLOR =================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/wlan1/tplink-bulb-color.wlan1.local.pcap"

# No signature found for both phone and device sides
OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/wlan1/tplink-bulb-color-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/timestamps/tplink-bulb-color-apr-12-2019.timestamps"
DEVICE_IP="192.168.1.246"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/wlan1/tplink-bulb-color.wlan1.ifttt.pcap"

# No signature found for both phone and device sides
OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb/tplink-bulb-color/wlan1/tplink-bulb-color-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-color/timestamps/tplink-bulb-color-ifttt-dec-18-2019.timestamps"
DEVICE_IP="192.168.1.140"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# =============================================== TP LINK BULB INTENSITY ===============================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/wlan1/tplink-bulb-intensity.wlan1.local.pcap"

# No signature found for both phone and device sides
OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/wlan1/tplink-bulb-intensity-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/timestamps/tplink-bulb-intensity-apr-29-2019.timestamps"
DEVICE_IP="192.168.1.246"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/wlan1/tplink-bulb-intensity.wlan1.ifttt.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb/tplink-bulb-intensity/wlan1/tplink-bulb-intensity-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/timestamps/tplink-bulb-intensity-ifttt-dec-17-2019.timestamps"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb/tplink-bulb-intensity/timestamps/tplink-bulb-intensity-ifttt-dec-18-2019.timestamps"
DEVICE_IP="192.168.1.140"
TIMEZONE="-7"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ==================================================== TP-LINK PLUG ====================================================
# LOCAL
# DEVICE SIDE (both the 112, 115 and 556, 1293 sequences)
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-plug/wlan1/tplink-plug.wlan1.local.pcap"

# LAN signature.
OUTPUT_PCAP="$OUTPUT_DIR/tplink-plug/wlan1/tplink-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-plug/timestamps/tplink-plug-nov-8-2018.timestamps"
DEVICE_IP="192.168.1.159"
TIMEZONE="-8"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE


# DEVICE SIDE OUTBOUND (contains only those packets that go through the WAN port, i.e., only the 556, 1293 sequence)
# WAN signature.
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE

# Phone side does not make sense as it is merely a subset of the device side and does not differentiate ONs from OFFs.
# ======================================================================================================================
# REMOTE
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-plug/wlan1/tplink-plug.wlan1.remote.pcap"

# LAN signature.
OUTPUT_PCAP="$OUTPUT_DIR/tplink-plug/wlan1/tplink-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-plug/timestamps/tplink-plug-dec-2-2019.timestamps"
DEVICE_IP="192.168.1.159"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-plug/wlan1/tplink-plug.wlan1.ifttt.pcap"

# LAN signature.
OUTPUT_PCAP="$OUTPUT_DIR/tplink-plug/wlan1/tplink-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-plug/timestamps/tplink-plug-ifttt-dec-10-2019.timestamps"
DEVICE_IP="192.168.1.159"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ================================================== WEMO INSIGHT PLUG =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/wemo-insight-plug/wlan1/wemo-insight-plug.wlan1.local.pcap"

# Has LAN signature.
OUTPUT_PCAP="$OUTPUT_DIR/wemo-insight-plug/wlan1/wemo-insight-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wemo-insight-plug/timestamps/wemo-insight-plug-nov-21-2018.timestamps"
DEVICE_IP="192.168.1.246"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/wemo-insight-plug/wlan1/wemo-insight-plug.wlan1.ifttt.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/wemo-insight-plug/wlan1/wemo-insight-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wemo-insight-plug/timestamps/wemo-insight-plug-ifttt-dec-14-2019.timestamps"
DEVICE_IP="192.168.1.136"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ===================================================== WEMO PLUG ======================================================
# LOCAL
INPUT_PCAP="$SIGNATURES_BASE_DIR/wemo-plug/wlan1/wemo-plug.wlan1.local.pcap"

# Has LAN signature.
OUTPUT_PCAP="$OUTPUT_DIR/wemo-plug/wlan1/wemo-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wemo-plug/timestamps/wemo-plug-nov-20-2018.timestamps"
DEVICE_IP="192.168.1.246"
TIMEZONE="-8"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================
# IFTTT
INPUT_PCAP="$SIGNATURES_BASE_DIR/wemo-plug/wlan1/wemo-plug.wlan1.ifttt.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/wemo-plug/wlan1/wemo-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wemo-plug/timestamps/wemo-plug-ifttt-dec-16-2019.timestamps"
DEVICE_IP="192.168.1.146"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# TODO: SAME VENDOR OBSERVATION (TP-LINK DEVICES)
# TODO: Use PCAP files in the same-vendor folder
# =============================================== TP-LINK TWO-OUTLET PLUG ==============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-two-outlet-plug/wlan1/tplink-two-outlet-plug.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-two-outlet-plug/wlan1/tplink-two-outlet-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-two-outlet-plug/timestamps/tplink-two-outlet-plug-dec-22-2019.timestamps"
DEVICE_IP="192.168.1.178"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ================================================= TP-LINK POWER STRIP ================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-power-strip/wlan1/tplink-power-strip.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-power-strip/wlan1/tplink-power-strip-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-power-strip/timestamps/tplink-power-strip-dec-22-2019.timestamps"
DEVICE_IP="192.168.1.142"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ============================================== TP-LINK LIGHT BULB ON/OFF =============================================
# KL-110 (newer model than LB-130 but no color---only dimmable white)
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb-white/tplink-bulb-white-onoff/wlan1/tplink-bulb-white-onoff.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb-white/tplink-bulb-white-onoff/wlan1/tplink-bulb-white-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb-white/tplink-bulb-white-onoff/timestamps/tplink-bulb-white-onoff-dec-21-2019.timestamps"
DEVICE_IP="192.168.1.227"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ============================================= TP-LINK LIGHT BULB INTENSITY ===========================================
# KL-110 (newer model than LB-130 but no color---only dimmable white)
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-bulb-white/tplink-bulb-white-intensity/wlan1/tplink-bulb-white-intensity.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-bulb-white/tplink-bulb-white-intensity/wlan1/tplink-bulb-white-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-bulb-white/tplink-bulb-white-intensity/timestamps/tplink-bulb-white-intensity-dec-21-2019.timestamps"
DEVICE_IP="192.168.1.227"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ================================================ TP-LINK CAMERA ON/OFF ===============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-camera/tplink-camera-onoff/wlan1/tplink-camera-onoff.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-camera/tplink-camera-onoff/wlan1/tplink-light-camera-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-camera/tplink-camera-onoff/timestamps/tplink-camera-onoff-dec-22-2019.timestamps"
DEVICE_IP="192.168.1.235"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# =============================================== TP-LINK CAMERA RECORDING =============================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-camera/tplink-camera-recording/wlan1/tplink-camera-recording.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-camera/tplink-camera-recording/wlan1/tplink-light-camera-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-camera/tplink-camera-recording/timestamps/tplink-camera-recording-dec-22-2019.timestamps"
DEVICE_IP="192.168.1.235"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# TODO: Mon(IoT)r PUBLIC DATASET
# TODO: Use PCAP files in the public-dataset folder
# TODO: For the TP-Link plug and WeMo Insight plug, the PCAP files in this folder are the results of retraining in December 2019
# ==================================================== TP-LINK PLUG ====================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/tplink-plug/wlan1/tplink-plug.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/tplink-plug/wlan1/tplink-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/tplink-plug/timestamps/tplink-plug-retraining-dec-25-2019.timestamps"
DEVICE_IP="192.168.1.160"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ================================================== WEMO INSIGHT PLUG =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/wemo-insight-plug/wlan1/wemo-insight-plug.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/wemo-insight-plug/wlan1/wemo-insight-plug-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/wemo-insight-plug/timestamps/wemo-insight-plug-retraining-jan-9-2020.timestamps"
# The format 192.168.10 is needed to generate packet length 260
DEVICE_IP="192.168.10.246"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# Mon(IoT)r DATASET
# ================================================= BLINK CAMERA WATCH =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-watch/wlan1/blink-camera-watch.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/blink-camera/blink-camera-watch/wlan1/blink-camera-watch-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-watch/timestamps/blink-camera-watch-retraining-dec-23-2019.timestamps"
DEVICE_IP="192.168.1.228"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================

# ================================================= BLINK CAMERA PHOTO =================================================
INPUT_PCAP="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-photo/wlan1/blink-camera-photo.wlan1.local.pcap"

OUTPUT_PCAP="$OUTPUT_DIR/blink-camera/blink-camera-photo/wlan1/blink-camera-photo-processed.pcap"
TIMESTAMP_FILE="$SIGNATURES_BASE_DIR/blink-camera/blink-camera-photo/timestamps/blink-camera-photo-retraining-dec-24-2019.timestamps"
DEVICE_IP="192.168.1.228"
TIMEZONE="-7"
OUTPUT_FILE="${TIMESTAMP_FILE%.*}-stats.txt"
#getMax $INPUT_PCAP $TIMESTAMP_FILE $DEVICE_IP $TIMEZONE > $OUTPUT_FILE
# ======================================================================================================================
