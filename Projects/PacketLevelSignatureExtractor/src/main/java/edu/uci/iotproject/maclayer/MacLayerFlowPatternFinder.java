package edu.uci.iotproject.maclayer;

import edu.uci.iotproject.FlowPattern;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.packet.RadiotapPacket;

import java.io.EOFException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeoutException;

/**
 * Performs a search for {@link FlowPattern}
 * TODO: May want to create an abstract FlowPatternFinder and then derive MacLayer, TcpipLayer FlowPatternFinders from that one.
 *
 * @author Janus Varmarken
 */
public class MacLayerFlowPatternFinder {

    private final MacLayerFlowPattern mPattern;
    private final PcapHandle mPcap;

    public MacLayerFlowPatternFinder(PcapHandle pcap, MacLayerFlowPattern pattern) {
        this.mPcap = Objects.requireNonNull(pcap,
                String.format("Argument of type '%s' cannot be null", PcapHandle.class.getSimpleName()));
        this.mPattern = Objects.requireNonNull(pattern,
                String.format("Argument of type '%s' cannot be null", FlowPattern.class.getSimpleName()));
    }

    public void findFlowPattern() {
        PcapPacket packet;
        try {
            // Packets matched to flow pattern searched for.
            List<PcapPacket> patternPackets = new ArrayList<>();
            while ((packet = mPcap.getNextPacketEx()) != null) {
                RadiotapPacket radiotapPacket;
                try {
                    // Some packets throw an IAE with message "msi must be between 0 and 6 but is actually: 7"
                    // when accessing the RadiotapPacket.
                    radiotapPacket = packet.get(RadiotapPacket.class);
                } catch (IllegalArgumentException iae) {
                    System.out.println(iae.getMessage());
                    continue;
                }
                if (radiotapPacket == null) {
                    continue;
                }
                // Restart search if pattern not found within reasonable time frame (hardcoded for now).
                if (patternPackets.size() > 0 && packet.getTimestamp().getEpochSecond() -
                            patternPackets.get(patternPackets.size()-1).getTimestamp().getEpochSecond() > 2) {
                    patternPackets = new ArrayList<>();
                }

                byte[] rawData = radiotapPacket.getPayload().getRawData();
                // Search rawData for MAC of FlowPattern in sender/receiver section
                // [TODO needs verification that this section is actually the sender/receiver section]
                if (rawData.length < 16) {
                    continue;
                }
                int prefixLength = mPattern.getMacPrefixRawBytes().length;
                byte[] mac1 = Arrays.copyOfRange(rawData, 4, prefixLength < 6 ? 4 + prefixLength : 10);
                byte[] mac2 = Arrays.copyOfRange(rawData, 10, prefixLength < 6 ? 10 + prefixLength : 16);
                if (!Arrays.equals(mac1, mPattern.getMacPrefixRawBytes()) && !Arrays.equals(mac2, mPattern.getMacPrefixRawBytes())) {
                    // MAC prefix not present in raw data.
                    continue;
                }
                // Packet related to device associated with the pattern we are looking for.
                int expectedLength = mPattern.getPacketLengthSequence().get(patternPackets.size());
                if (packet.length() == expectedLength) {
                    patternPackets.add(packet);
                    if (patternPackets.size() == mPattern.getLength()) {
                        // Full pattern found, declare success if packets are within some reasonable amount of time of
                        // one another.
                        // For now, we use a hardcoded value.
                        if (patternPackets.get(patternPackets.size()-1).getTimestamp().getEpochSecond() -
                                patternPackets.get(0).getTimestamp().getEpochSecond() < 5) {
                            System.out.println(String.format("[ find ] Detected a COMPLETE MATCH of pattern '%s' at %s!",
                                    mPattern.getPatternId(), patternPackets.get(0).getTimestamp().toString()));
                        }
                        // Reset search by resetting list.
                        patternPackets = new ArrayList<>();
                    }
                } else {
                    // Discard packet, not relevant to pattern.
                    continue;
                }
            }
        } catch (EOFException e) {
            // TODO wait for, and print, results.
        } catch (PcapNativeException|TimeoutException|NotOpenException e) {
            e.printStackTrace();
        }
    }

}


