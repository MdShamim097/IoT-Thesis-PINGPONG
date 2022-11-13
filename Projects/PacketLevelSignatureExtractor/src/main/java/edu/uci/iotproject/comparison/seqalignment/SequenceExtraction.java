package edu.uci.iotproject.comparison.seqalignment;

import edu.uci.iotproject.trafficreassembly.layer3.Conversation;
import edu.uci.iotproject.analysis.TcpConversationUtils;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * TODO add class documentation.
 *
 * @author Janus Varmarken
 */
public class SequenceExtraction {


    private final SequenceAlignment<Integer> mAlignmentAlg;


    public SequenceExtraction() {
        mAlignmentAlg = new SequenceAlignment<>(new AlignmentPricer<>((i1,i2) -> Math.abs(i1-i2), i -> 10));
    }


    public SequenceExtraction(SequenceAlignment<Integer> alignmentAlgorithm) {
        mAlignmentAlg = alignmentAlgorithm;
    }

    /**
     * Gets the {@link SequenceAlignment} used to perform the sequence extraction.
     * @return the {@link SequenceAlignment} used to perform the sequence extraction.
     */
    public SequenceAlignment<Integer> getAlignmentAlgorithm() {
        return mAlignmentAlg;
    }

    // Initial
//    /**
//     *
//     * @param convsForAction A set of {@link Conversation}s known to be associated with a single type of user action.
//     */
//    public void extract(List<Conversation> convsForAction) {
//        int maxDifference = 0;
//
//        for (int i = 0; i < convsForAction.size(); i++) {
//            for (int j = i+1; j < convsForAction.size(); i++) {
//                Integer[] sequence1 = getPacketLengthSequence(convsForAction.get(i));
//                Integer[] sequence2 = getPacketLengthSequence(convsForAction.get(j));
//                int alignmentCost = mAlignmentAlg.calculateAlignment(sequence1, sequence2);
//                if (alignmentCost > maxDifference) {
//                    maxDifference = alignmentCost;
//                }
//            }
//        }
//
//    }


//    public void extract(Map<String, List<Conversation>> hostnameToConvs) {
//        int maxDifference = 0;
//
//        for (int i = 0; i < convsForAction.size(); i++) {
//            for (int j = i+1; j < convsForAction.size(); i++) {
//                Integer[] sequence1 = getPacketLengthSequence(convsForAction.get(i));
//                Integer[] sequence2 = getPacketLengthSequence(convsForAction.get(j));
//                int alignmentCost = mAlignmentAlg.calculateAlignment(sequence1, sequence2);
//                if (alignmentCost > maxDifference) {
//                    maxDifference = alignmentCost;
//                }
//            }
//        }
//
//    }

    // Building signature from entire sequence
    public ExtractedSequence extract(List<Conversation> convsForActionForHostname) {
        // First group conversations by packet sequences.
        // TODO: the introduction of SYN/SYNACK, FIN/FINACK and RST as part of the sequence ID may be undesirable here
        // as it can potentially result in sequences that are equal in terms of payload packets to be considered
        // different due to differences in how they are terminated.
        Map<String, List<Conversation>> groupedBySequence =
                TcpConversationUtils.groupConversationsByPacketSequence(convsForActionForHostname, false);

        // Then get a hold of one of the conversations that gave rise to the most frequent sequence.
        Conversation mostFrequentConv = null;
        int maxFrequency = 0;
        for (Map.Entry<String, List<Conversation>> seqMapEntry : groupedBySequence.entrySet()) {
            if (seqMapEntry.getValue().size() > maxFrequency) {
                // Found a more frequent sequence
                maxFrequency = seqMapEntry.getValue().size();
                // We just pick the first conversation as the representative conversation for this sequence type.
                mostFrequentConv = seqMapEntry.getValue().get(0);
            } else if (seqMapEntry.getValue().size() == maxFrequency) {
                // This sequence has the same frequency as the max frequency seen so far.
                // Break ties by choosing the longest sequence.
                // First get an arbitrary representative of currently examined sequence; we just pick the first.
                Conversation c = seqMapEntry.getValue().get(0);
                mostFrequentConv = c.getPackets().size() > mostFrequentConv.getPackets().size() ? c : mostFrequentConv;
            }
        }
        // Now find the maximum cost of aligning the most frequent (or, alternatively longest) conversation with the
        // each of the rest of the conversations also associated with this action and hostname.
        int maxCost = 0;
        final Integer[] mostFrequentConvSeq = TcpConversationUtils.getPacketLengthSequence(mostFrequentConv);
        for (Conversation c : convsForActionForHostname) {
            if (c == mostFrequentConv) {
                // Don't compute distance to self.
                continue;
            }
            Integer[] cSeq = TcpConversationUtils.getPacketLengthSequence(c);
            int alignmentCost = mAlignmentAlg.calculateAlignment(mostFrequentConvSeq, cSeq);
            if (alignmentCost > maxCost) {
                maxCost = alignmentCost;
            }
        }
        return new ExtractedSequence(mostFrequentConv, maxCost, false);
    }

    // Building signature from only TLS Application Data packets
    public ExtractedSequence extractByTlsAppData(List<Conversation> convsForActionForHostname) {
        // TODO: temporary hack to avoid 97-only conversations for dlink plug. We need some preprocessing/data cleaning.
        convsForActionForHostname = convsForActionForHostname.stream().filter(c -> c.getTlsApplicationDataPackets().size() > 1).collect(Collectors.toList());

        Map<String, List<Conversation>> groupedByTlsAppDataSequence =
                TcpConversationUtils.groupConversationsByTlsApplicationDataPacketSequence(convsForActionForHostname);
        // Get a Conversation representing the most frequent TLS application data sequence.
        Conversation mostFrequentConv = groupedByTlsAppDataSequence.values().stream().max((l1, l2) -> {
            // The frequency of a conversation with a specific packet sequence is the list size as that represents how
            // many conversations exhibit that packet sequence.
            // Hence, the difference between the list sizes can be used directly as the return value of the Comparator.
            // Note: we break ties by choosing the one with the most TLS application data packets (i.e., the longest
            // sequence) in case the frequencies are equal.
            int diff = l1.size() - l2.size();
            return diff != 0 ? diff : l1.get(0).getTlsApplicationDataPackets().size() - l2.get(0).getTlsApplicationDataPackets().size();
        }).get().get(0); // Just pick the first as a representative of the most frequent sequence.
        // Lengths of TLS Application Data packets in the most frequent (or most frequent and longest) conversation.
        Integer[] mostFreqSeq = TcpConversationUtils.getPacketLengthSequenceTlsAppDataOnly(mostFrequentConv);
        // Now find the maximum cost of aligning the most frequent (or, alternatively longest) conversation with the
        // each of the rest of the conversations also associated with this action and hostname.
        int maxCost = 0;
        for (Conversation c : convsForActionForHostname) {
            if (c == mostFrequentConv) continue;
            int cost = mAlignmentAlg.calculateAlignment(mostFreqSeq, TcpConversationUtils.getPacketLengthSequenceTlsAppDataOnly(c));
            maxCost = cost > maxCost ? cost : maxCost;
        }
        return new ExtractedSequence(mostFrequentConv, maxCost, true);
        // Now find the maximum cost of aligning the most frequent (or, alternatively longest) conversation with the
        // each of the rest of the conversations also associated with this action and hostname.
    }

}
