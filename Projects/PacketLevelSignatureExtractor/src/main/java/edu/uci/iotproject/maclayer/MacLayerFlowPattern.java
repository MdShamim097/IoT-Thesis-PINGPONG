package edu.uci.iotproject.maclayer;

import java.util.Collections;
import java.util.List;

/**
 * TODO create base class for FlowPattern and derive MacLayer, TCP/IP layer versions from that.
 *
 * @author Janus Varmarken
 */
public class MacLayerFlowPattern {

    private final List<Integer> mPacketLengthSequence;
    private final String mMacPrefix;
    private final String mPatternId;
    private final byte[] mMacPreixBytes;

    public MacLayerFlowPattern(String patternId, String macPrefix, List<Integer> packetLengthSequence) {
        mMacPrefix = macPrefix;
        mPatternId = patternId;
        mPacketLengthSequence = packetLengthSequence;
        // Conversion provided by https://stackoverflow.com/a/10839361/1214974
        String[] addressParts = macPrefix.split(":");
        mMacPreixBytes = new byte[addressParts.length];
        for(int i = 0; i < mMacPreixBytes.length; i++) {
            Integer hex  = Integer.parseInt(addressParts[i], 16);
            mMacPreixBytes[i] = hex.byteValue();
        }
    }

    public String getPatternId() {
        return mPatternId;
    }

    public byte[] getMacPrefixRawBytes() {
        return mMacPreixBytes;
    }

    public List<Integer> getPacketLengthSequence() {
        return Collections.unmodifiableList(mPacketLengthSequence);
    }

    public int getLength() {
        return mPacketLengthSequence.size();
    }
}
