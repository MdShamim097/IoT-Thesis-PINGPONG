package edu.uci.iotproject.comparison.seqalignment;

import edu.uci.iotproject.trafficreassembly.layer3.Conversation;
import org.pcap4j.core.PcapPacket;

import java.util.List;

/**
 * TODO add class documentation.
 *
 * @author Janus Varmarken
 */
public class ExtractedSequence {

    private final Conversation mRepresentativeSequence;

    private final int mMaxAlignmentCost;

    private final String mSequenceString;

    public ExtractedSequence(Conversation sequence, int maxAlignmentCost, boolean tlsAppDataAlignment) {
        mRepresentativeSequence = sequence;
        mMaxAlignmentCost = maxAlignmentCost;
        StringBuilder sb = new StringBuilder();
        List<PcapPacket> pkts = tlsAppDataAlignment ? sequence.getTlsApplicationDataPackets() : sequence.getPackets();
        pkts.forEach(p -> {
            if (sb.length() != 0) sb.append(" ");
            sb.append(p.getOriginalLength());
        });
        mSequenceString = sb.toString();
    }

    public Conversation getRepresentativeSequence() {
        return mRepresentativeSequence;
    }

    public int getMaxAlignmentCost() {
        return mMaxAlignmentCost;
    }

}
