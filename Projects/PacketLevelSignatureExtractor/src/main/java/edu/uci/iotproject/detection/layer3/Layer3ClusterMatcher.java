package edu.uci.iotproject.detection.layer3;

import edu.uci.iotproject.analysis.TriggerTrafficExtractor;
import edu.uci.iotproject.detection.AbstractClusterMatcher;
import edu.uci.iotproject.detection.ClusterMatcherObserver;
import edu.uci.iotproject.trafficreassembly.layer3.Conversation;
import edu.uci.iotproject.trafficreassembly.layer3.TcpReassembler;
import edu.uci.iotproject.analysis.TcpConversationUtils;
import edu.uci.iotproject.io.PcapHandleReader;
import edu.uci.iotproject.util.PrintUtils;
import org.pcap4j.core.*;

import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;

import static edu.uci.iotproject.util.PcapPacketUtils.*;

/**
 * Searches a traffic trace for sequences of packets "belong to" a given cluster (in other words, attempts to classify
 * traffic as pertaining to a given cluster).
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class Layer3ClusterMatcher extends AbstractClusterMatcher implements PacketListener {

    /**
     * The ordered directions of packets in the sequences that make up {@link #mCluster}.
     */
    private final Conversation.Direction[] mClusterMemberDirections;

    /**
     * For reassembling the observed traffic into TCP connections.
     */
    private final TcpReassembler mTcpReassembler;

    /**
     * IP of the router's WAN port (if analyzed traffic is captured at the ISP's point of view).
     */
    private final String mRouterWanIp;

    /**
     * Epsilon value used by the DBSCAN algorithm; it is used again for range-based matching here.
     */
    private final double mEps;

    /**
     * The packet inclusion time for signature.
     */
    private int mInclusionTimeMillis;
    private int mInclusionPacketNumbers;
    /**
     * Relaxed matching
     */
    private int mDelta;
    private Set<Integer> mPacketSet;

    /**
     * Create a {@link Layer3ClusterMatcher}.
     * @param cluster The cluster that traffic is matched against.
     * @param routerWanIp The router's WAN IP if examining traffic captured at the ISP's point of view (used for
     *                    determining the direction of packets).
     * @param inclusionTimeMillis The packet inclusion time for signature.
     * @param isRangeBased The boolean that decides if it is range-based vs. strict matching.
     * @param eps The epsilon value used in the DBSCAN algorithm.
     * @param detectionObservers Client code that wants to get notified whenever the {@link Layer3ClusterMatcher} detects that
     *                          (a subset of) the examined traffic is similar to the traffic that makes up
     *                          {@code cluster}, i.e., when the examined traffic is classified as pertaining to
     *                          {@code cluster}.
     */
    public Layer3ClusterMatcher(List<List<PcapPacket>> cluster, String routerWanIp, 
                                //int inclusionTimeMillis,
                                int inclusionPacketNumbers,
                                boolean isRangeBased, double eps, int delta, Set<Integer> packetSet,
                                ClusterMatcherObserver... detectionObservers) {
        super(cluster, isRangeBased);
        Objects.requireNonNull(detectionObservers, "detectionObservers cannot be null");
        for (ClusterMatcherObserver obs : detectionObservers) {
            addObserver(obs);
        }
        // Build the cluster members' direction sequence.
        // Note: assumes that the provided cluster was captured within the local network (routerWanIp is set to null).
        mClusterMemberDirections = getPacketDirections(cluster.get(0), null);
        /*
         * Enforce restriction on cluster members: all representatives must exhibit the same direction pattern and
         * contain the same number of packets. Note that this is a somewhat heavy operation, so it may be disabled later
         * on in favor of performance. However, it is only run once (at instantiation), so the overhead may be warranted
         * in order to ensure correctness, especially during the development/debugging phase.
         */
        if (!isRangeBased) {    // Only when it is not range-based
            if (mCluster.stream().
                    anyMatch(inner -> !Arrays.equals(mClusterMemberDirections, getPacketDirections(inner, null)))) {
                throw new IllegalArgumentException(
                        "cluster members must contain the same number of packets and exhibit the same packet direction " +
                                "pattern"
                );
            }
        }
        mEps = eps;
        mRouterWanIp = routerWanIp;
				mTcpReassembler = new TcpReassembler(mRouterWanIp);
        /*
        mInclusionTimeMillis =
                inclusionTimeMillis == 0 ? TriggerTrafficExtractor.INCLUSION_WINDOW_MILLIS : inclusionTimeMillis;
        */
        mInclusionPacketNumbers = 
                inclusionPacketNumbers == 0 ? TriggerTrafficExtractor.INCLUSION_NUMBER_OF_PACKETS : inclusionPacketNumbers;
        
        mDelta = delta;
        mPacketSet = packetSet;
    }

    @Override
    public void gotPacket(PcapPacket packet) {
        // Present packet to TCP reassembler so that it can be mapped to a connection (if it is a TCP packet).
        mTcpReassembler.gotPacket(packet);
    }

    /**
     * Get the cluster that describes the packet sequence that this {@link Layer3ClusterMatcher} is searching for.
     * @return the cluster that describes the packet sequence that this {@link Layer3ClusterMatcher} is searching for.
     */
    public List<List<PcapPacket>> getCluster() {
        return mCluster;
    }

    public void performDetectionRangeBased() {
        /*
         * Let's start out simple by building a version that only works for signatures that do not span across multiple
         * TCP conversations...
         */
        for (Conversation c : mTcpReassembler.getTcpConversations()) {
            if (c.isTls() && c.getTlsApplicationDataPackets().isEmpty() || !c.isTls() && c.getPackets().isEmpty()) {
                // Skip empty conversations.
                continue;
            }
            List<PcapPacket> lowerBound = mCluster.get(0);
            List<PcapPacket> upperBound = mCluster.get(1);
            if (isTlsSequence(lowerBound) != c.isTls() || isTlsSequence(upperBound) != c.isTls()) {
                // We consider it a mismatch if one is a TLS application data sequence and the other is not.
                continue;
            }
            // Fetch set of packets to examine based on TLS or not.
            List<PcapPacket> cPkts = c.isTls() ? c.getTlsApplicationDataPackets() : c.getPackets();
            Optional<List<PcapPacket>> match;
            while ((match = findSubsequenceInSequence(lowerBound, upperBound, cPkts, mClusterMemberDirections, null)).
                    isPresent()) {
                List<PcapPacket> matchSeq = match.get();
                // Notify observers about the match.
                // Max number of skipped packets in layer 3 is 0 (no skipped packets)
                mObservers.forEach(o -> o.onMatch(Layer3ClusterMatcher.this, matchSeq));
                /*
                 * Get the index in cPkts of the last packet in the sequence of packets that matches the searched
                 * signature sequence.
                 */
                int matchSeqEndIdx = cPkts.indexOf(matchSeq.get(matchSeq.size() - 1));
                // We restart the search for the signature sequence immediately after that index, so truncate cPkts.
                cPkts = cPkts.stream().skip(matchSeqEndIdx + 1).collect(Collectors.toList());
            }
        }
    }

    // TODO: Relaxed matching with delta is only applied to conservative matching for now
    public void performDetectionConservative() {
        /*
         * Let's start out simple by building a version that only works for signatures that do not span across multiple
         * TCP conversations...
         */
        for (Conversation c : mTcpReassembler.getTcpConversations()) {
            if (c.isTls() && c.getTlsApplicationDataPackets().isEmpty() || !c.isTls() && c.getPackets().isEmpty()) {
                // Skip empty conversations.
                continue;
            }
            for (List<PcapPacket> signatureSequence : mCluster) {
                if (isTlsSequence(signatureSequence) != c.isTls()) {
                    // We consider it a mismatch if one is a TLS application data sequence and the other is not.
                    continue;
                }
                // Fetch set of packets to examine based on TLS or not.
                List<PcapPacket> cPkts = c.isTls() ? c.getTlsApplicationDataPackets() : c.getPackets();
                /*
                 * Note: we embed the attempt to detect the signature sequence in a loop in order to capture those cases
                 * where the same signature sequence appears multiple times in one Conversation.
                 *
                 * Note: since we expect all sequences that together make up the signature to exhibit the same direction
                 * pattern, we can simply pass the precomputed direction array for the signature sequence so that it
                 * won't have to be recomputed internally in each call to findSubsequenceInSequence().
                 */
                Optional<List<PcapPacket>> match;
                while ((match = findSubsequenceInSequence(signatureSequence, cPkts, mClusterMemberDirections, null, mDelta, mPacketSet)).
                        isPresent()) {
                    List<PcapPacket> matchSeq = match.get();
                    // Notify observers about the match.
                    // Max number of skipped packets in layer 3 is 0 (no skipped packets)
                    mObservers.forEach(o -> o.onMatch(Layer3ClusterMatcher.this, matchSeq));
                    /*
                     * Get the index in cPkts of the last packet in the sequence of packets that matches the searched
                     * signature sequence.
                     */
                    int matchSeqEndIdx = cPkts.indexOf(matchSeq.get(matchSeq.size() - 1));
                    // We restart the search for the signature sequence immediately after that index, so truncate cPkts.
                    cPkts = cPkts.stream().skip(matchSeqEndIdx + 1).collect(Collectors.toList());
                }
            }

            /*
             * TODO:
             * if no item in cluster matches, also perform a distance-based matching to cover those cases where we did
             * not manage to capture every single mutation of the sequence during training.
             *
             * Need to compute average/centroid of cluster to do so...? Compute within-cluster variance, then check if
             * distance between input conversation and cluster average/centroid is smaller than or equal to the computed
             * variance?
             */
        }
    }

    /**
     * Checks if {@code sequence} is a sequence of TLS packets. Note: the current implementation relies on inspection
     * of the port numbers when deciding between TLS vs. non-TLS. Therefore, only the first packet of {@code sequence}
     * is examined as it is assumed that all packets in {@code sequence} pertain to the same {@link Conversation} and
     * hence share the same set of two src/dst port numbers (albeit possibly alternating between which one is the src
     * and which one is the dst, as packets in {@code sequence} may be in alternating directions).
     * @param sequence The sequence of packets for which it is to be determined if it is a sequence of TLS packets or
     *                 non-TLS packets.
     * @return {@code true} if {@code sequence} is a sequence of TLS packets, {@code false} otherwise.
     */
    private boolean isTlsSequence(List<PcapPacket> sequence) {
        // NOTE: Assumes ALL packets in sequence pertain to the same TCP connection!
        PcapPacket firstPkt = sequence.get(0);
        int srcPort = getSourcePort(firstPkt);
        int dstPort = getDestinationPort(firstPkt);
        return TcpConversationUtils.isTlsPort(srcPort) || TcpConversationUtils.isTlsPort(dstPort);
    }

    /**
     * Examine if a given sequence of packets ({@code sequence}) contains a given shorter sequence of packets
     * ({@code subsequence}). Note: the current implementation actually searches for a substring as it does not allow
     * for interleaving packets in {@code sequence} that are not in {@code subsequence}; for example, if
     * {@code subsequence} consists of packet lengths [2, 3, 5] and {@code sequence} consists of  packet lengths
     * [2, 3, 4, 5], the result will be that there is no match (because of the interleaving 4). If we are to allow
     * interleaving packets, we need a modified version of
     * <a href="https://stackoverflow.com/a/20545604/1214974">this</a>.
     *
     * @param subsequence The sequence to search for.
     * @param sequence The sequence to search.
     * @param subsequenceDirections The directions of packets in {@code subsequence} such that for all {@code i},
     *                              {@code subsequenceDirections[i]} is the direction of the packet returned by
     *                              {@code subsequence.get(i)}. May be set to {@code null}, in which this call will
     *                              internally compute the packet directions.
     * @param sequenceDirections The directions of packets in {@code sequence} such that for all {@code i},
     *                           {@code sequenceDirections[i]} is the direction of the packet returned by
     *                           {@code sequence.get(i)}. May be set to {@code null}, in which this call will internally
     *                           compute the packet directions.
     *
     * @return An {@link Optional} containing the part of {@code sequence} that matches {@code subsequence}, or an empty
     *         {@link Optional} if no part of {@code sequence} matches {@code subsequence}.
     */
    private Optional<List<PcapPacket>> findSubsequenceInSequence(List<PcapPacket> subsequence,
                                                                 List<PcapPacket> sequence,
                                                                 Conversation.Direction[] subsequenceDirections,
                                                                 Conversation.Direction[] sequenceDirections) {
        if (sequence.size() < subsequence.size()) {
            // If subsequence is longer, it cannot be contained in sequence.
            return Optional.empty();
        }
        if (isTlsSequence(subsequence) != isTlsSequence(sequence)) {
            // We consider it a mismatch if one is a TLS application data sequence and the other is not.
            return Optional.empty();
        }
        // If packet directions have not been precomputed by calling code, we need to construct them.
        if (subsequenceDirections == null) {
            subsequenceDirections = getPacketDirections(subsequence, mRouterWanIp);
        }
        if (sequenceDirections == null) {
            sequenceDirections = getPacketDirections(sequence, mRouterWanIp);
        }
        int subseqIdx = 0;
        int seqIdx = 0;
        while (seqIdx < sequence.size()) {
            PcapPacket subseqPkt = subsequence.get(subseqIdx);
            PcapPacket seqPkt = sequence.get(seqIdx);
            // We only have a match if packet lengths and directions match.
            if (subseqPkt.getOriginalLength() == seqPkt.getOriginalLength() &&
                    subsequenceDirections[subseqIdx] == sequenceDirections[seqIdx]) {
                // A match; advance both indices to consider next packet in subsequence vs. next packet in sequence.
                subseqIdx++;
                seqIdx++;
                if (subseqIdx == subsequence.size()) {
                    // We managed to match the entire subsequence in sequence.
                    // Return the sublist of sequence that matches subsequence.
                    /*
                     * TODO:
                     * ASSUMES THE BACKING LIST (i.e., 'sequence') IS _NOT_ STRUCTURALLY MODIFIED, hence may not work
                     * for live traces!
                     */
                    return Optional.of(sequence.subList(seqIdx - subsequence.size(), seqIdx));
                }
            } else {
                // Mismatch.
                if (subseqIdx > 0) {
                    /*
                     * If we managed to match parts of subsequence, we restart the search for subsequence in sequence at
                     * the index of sequence where the current mismatch occurred. I.e., we must reset subseqIdx, but
                     * leave seqIdx untouched.
                     */
                    subseqIdx = 0;
                } else {
                    /*
                     * First packet of subsequence didn't match packet at seqIdx of sequence, so we move forward in
                     * sequence, i.e., we continue the search for subsequence in sequence starting at index seqIdx+1 of
                     * sequence.
                     */
                    seqIdx++;
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Overload the same method with relaxed matching.
     *
     * @param subsequence The sequence to search for.
     * @param sequence The sequence to search.
     * @param subsequenceDirections The directions of packets in {@code subsequence} such that for all {@code i},
     *                              {@code subsequenceDirections[i]} is the direction of the packet returned by
     *                              {@code subsequence.get(i)}. May be set to {@code null}, in which this call will
     *                              internally compute the packet directions.
     * @param sequenceDirections The directions of packets in {@code sequence} such that for all {@code i},
     *                           {@code sequenceDirections[i]} is the direction of the packet returned by
     *                           {@code sequence.get(i)}. May be set to {@code null}, in which this call will internally
     *                           compute the packet directions.
     * @param delta The delta for relaxed matching
     * @param packetSet The set of unique packet lengths, whose matching is to be relaxed
     *
     * @return An {@link Optional} containing the part of {@code sequence} that matches {@code subsequence}, or an empty
     *         {@link Optional} if no part of {@code sequence} matches {@code subsequence}.
     */
    private Optional<List<PcapPacket>> findSubsequenceInSequence(List<PcapPacket> subsequence,
                                                                 List<PcapPacket> sequence,
                                                                 Conversation.Direction[] subsequenceDirections,
                                                                 Conversation.Direction[] sequenceDirections,
                                                                 int delta,
                                                                 Set<Integer> packetSet) {
        if (sequence.size() < subsequence.size()) {
            // If subsequence is longer, it cannot be contained in sequence.
            return Optional.empty();
        }
        if (isTlsSequence(subsequence) != isTlsSequence(sequence)) {
            // We consider it a mismatch if one is a TLS application data sequence and the other is not.
            return Optional.empty();
        }
        // If packet directions have not been precomputed by calling code, we need to construct them.
        if (subsequenceDirections == null) {
            subsequenceDirections = getPacketDirections(subsequence, mRouterWanIp);
        }
        if (sequenceDirections == null) {
            sequenceDirections = getPacketDirections(sequence, mRouterWanIp);
        }
        int subseqIdx = 0;
        int seqIdx = 0;
        while (seqIdx < sequence.size()) {
            PcapPacket subseqPkt = subsequence.get(subseqIdx);
            PcapPacket seqPkt = sequence.get(seqIdx);
            // We only have a match if packet lengths and directions match.
            // Do relaxed matching here if applicable
            if ((delta > 0 && packetSet.contains(subseqPkt.getOriginalLength()) &&
                    subseqPkt.getOriginalLength() - delta <= seqPkt.getOriginalLength() &&
                    seqPkt.getOriginalLength() <= subseqPkt.getOriginalLength() + delta &&
                    subsequenceDirections[subseqIdx] == sequenceDirections[seqIdx]) ||
                    // Or just exact matching
                    (subseqPkt.getOriginalLength() == seqPkt.getOriginalLength() &&
                     subsequenceDirections[subseqIdx] == sequenceDirections[seqIdx])) {
                // A match; advance both indices to consider next packet in subsequence vs. next packet in sequence.
                subseqIdx++;
                seqIdx++;
                if (subseqIdx == subsequence.size()) {
                    // We managed to match the entire subsequence in sequence.
                    // Return the sublist of sequence that matches subsequence.
                    /*
                     * TODO:
                     * ASSUMES THE BACKING LIST (i.e., 'sequence') IS _NOT_ STRUCTURALLY MODIFIED, hence may not work
                     * for live traces!
                     */
                    return Optional.of(sequence.subList(seqIdx - subsequence.size(), seqIdx));
                }
            } else {
                // Mismatch.
                if (subseqIdx > 0) {
                    /*
                     * If we managed to match parts of subsequence, we restart the search for subsequence in sequence at
                     * the index of sequence where the current mismatch occurred. I.e., we must reset subseqIdx, but
                     * leave seqIdx untouched.
                     */
                    subseqIdx = 0;
                } else {
                    /*
                     * First packet of subsequence didn't match packet at seqIdx of sequence, so we move forward in
                     * sequence, i.e., we continue the search for subsequence in sequence starting at index seqIdx+1 of
                     * sequence.
                     */
                    seqIdx++;
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Overloading the method {@code findSubsequenceInSequence} for range-based matching. Instead of a sequence,
     * we have sequences of lower and upper bounds.
     *
     * @param lowerBound The lower bound of the sequence we search for.
     * @param upperBound The upper bound of the sequence we search for.
     * @param subsequenceDirections The directions of packets in {@code subsequence} such that for all {@code i},
     *                              {@code subsequenceDirections[i]} is the direction of the packet returned by
     *                              {@code subsequence.get(i)}. May be set to {@code null}, in which this call will
     *                              internally compute the packet directions.
     * @param sequenceDirections The directions of packets in {@code sequence} such that for all {@code i},
     *                           {@code sequenceDirections[i]} is the direction of the packet returned by
     *                           {@code sequence.get(i)}. May be set to {@code null}, in which this call will internally
     *                           compute the packet directions.
     *
     * @return An {@link Optional} containing the part of {@code sequence} that matches {@code subsequence}, or an empty
     *         {@link Optional} if no part of {@code sequence} matches {@code subsequence}.
     */
    private Optional<List<PcapPacket>> findSubsequenceInSequence(List<PcapPacket> lowerBound,
                                                                 List<PcapPacket> upperBound,
                                                                 List<PcapPacket> sequence,
                                                                 Conversation.Direction[] subsequenceDirections,
                                                                 Conversation.Direction[] sequenceDirections) {
        // Just do the checks for either lower or upper bound!
        // TODO: For now we use just the lower bound
        if (sequence.size() < lowerBound.size()) {
            // If subsequence is longer, it cannot be contained in sequence.
            return Optional.empty();
        }
        if (isTlsSequence(lowerBound) != isTlsSequence(sequence)) {
            // We consider it a mismatch if one is a TLS application data sequence and the other is not.
            return Optional.empty();
        }
        // If packet directions have not been precomputed by calling code, we need to construct them.
        if (subsequenceDirections == null) {
            subsequenceDirections = getPacketDirections(lowerBound, mRouterWanIp);
        }
        if (sequenceDirections == null) {
            sequenceDirections = getPacketDirections(sequence, mRouterWanIp);
        }
        int subseqIdx = 0;
        int seqIdx = 0;
        while (seqIdx < sequence.size()) {
            PcapPacket lowBndPkt = lowerBound.get(subseqIdx);
            PcapPacket upBndPkt = upperBound.get(subseqIdx);
            PcapPacket seqPkt = sequence.get(seqIdx);
            // We only have a match if packet lengths and directions match.
            // The packet lengths have to be in the range of [lowerBound - eps, upperBound+eps]
            // We initialize the lower and upper bounds first
            int epsLowerBound = lowBndPkt.length();
            int epsUpperBound = upBndPkt.length();
            // Do strict matching if the lower and upper bounds are the same length
            // Do range matching with eps otherwise
            if (epsLowerBound != epsUpperBound) {
                // TODO: Maybe we could do better here for the double to integer conversion?
                epsLowerBound = epsLowerBound - (int) mEps;
                epsUpperBound = epsUpperBound + (int) mEps;
            }
            if (epsLowerBound <= seqPkt.getOriginalLength() &&
                    seqPkt.getOriginalLength() <= epsUpperBound &&
                    subsequenceDirections[subseqIdx] == sequenceDirections[seqIdx]) {
                // A match; advance both indices to consider next packet in subsequence vs. next packet in sequence.
                subseqIdx++;
                seqIdx++;
                if (subseqIdx == lowerBound.size()) {
                    // We managed to match the entire subsequence in sequence.
                    // Return the sublist of sequence that matches subsequence.
                    /*
                     * TODO:
                     * ASSUMES THE BACKING LIST (i.e., 'sequence') IS _NOT_ STRUCTURALLY MODIFIED, hence may not work
                     * for live traces!
                     */
                    return Optional.of(sequence.subList(seqIdx - lowerBound.size(), seqIdx));
                }
            } else {
                // Mismatch.
                if (subseqIdx > 0) {
                    /*
                     * If we managed to match parts of subsequence, we restart the search for subsequence in sequence at
                     * the index of sequence where the current mismatch occurred. I.e., we must reset subseqIdx, but
                     * leave seqIdx untouched.
                     */
                    subseqIdx = 0;
                } else {
                    /*
                     * First packet of subsequence didn't match packet at seqIdx of sequence, so we move forward in
                     * sequence, i.e., we continue the search for subsequence in sequence starting at index seqIdx+1 of
                     * sequence.
                     */
                    seqIdx++;
                }
            }
        }
        return Optional.empty();
    }

    // TODO: EXPERIMENT WITH ONLY PACKET DIRECTION AND TIMING
//    private Optional<List<PcapPacket>> findSubsequenceInSequence(List<PcapPacket> subsequence,
//                                                                 List<PcapPacket> sequence,
//                                                                 Conversation.Direction[] subsequenceDirections,
//                                                                 Conversation.Direction[] sequenceDirections) {
//        if (sequence.size() < subsequence.size()) {
//            // If subsequence is longer, it cannot be contained in sequence.
//            return Optional.empty();
//        }
//        if (isTlsSequence(subsequence) != isTlsSequence(sequence)) {
//            // We consider it a mismatch if one is a TLS application data sequence and the other is not.
//            return Optional.empty();
//        }
//        // If packet directions have not been precomputed by calling code, we need to construct them.
//        if (subsequenceDirections == null) {
//            subsequenceDirections = getPacketDirections(subsequence, mRouterWanIp);
//        }
//        if (sequenceDirections == null) {
//            sequenceDirections = getPacketDirections(sequence, mRouterWanIp);
//        }
//        int subseqIdx = 0;
//        int seqIdx = 0;
//        while (subseqIdx < subsequence.size() && seqIdx < sequence.size()) {
//            // We only have a match if packet lengths and directions match.
//            if (subsequenceDirections[subseqIdx] == sequenceDirections[seqIdx]) {
//                // A match; advance both indices to consider next packet in subsequence vs. next packet in sequence.
//                subseqIdx++;
//                seqIdx++;
//                if (subseqIdx == subsequence.size()) {
//                    // We managed to match the entire subsequence in sequence.
//                    // Return the sublist of sequence that matches subsequence.
//                    /*
//                     * TODO:
//                     * ASSUMES THE BACKING LIST (i.e., 'sequence') IS _NOT_ STRUCTURALLY MODIFIED, hence may not work
//                     * for live traces!
//                     */
//                    // TODO: ALSO CHECK TIMING CONSTRAINT
//                    PcapPacket firstPacket = sequence.get(seqIdx - subsequence.size());
//                    PcapPacket lastPacket = sequence.get(seqIdx-1);
//                    if (!lastPacket.getTimestamp().isAfter(firstPacket.getTimestamp().plusMillis(mInclusionTimeMillis))) {
//                        return Optional.of(sequence.subList(seqIdx - subsequence.size(), seqIdx));
//                    }
//                }
//            } else {
//                // Mismatch.
//                if (subseqIdx > 0) {
//                    /*
//                     * If we managed to match parts of subsequence, we restart the search for subsequence in sequence at
//                     * the index of sequence where the current mismatch occurred. I.e., we must reset subseqIdx, but
//                     * leave seqIdx untouched.
//                     */
//                    subseqIdx = 0;
//                } else {
//                    /*
//                     * First packet of subsequence didn't match packet at seqIdx of sequence, so we move forward in
//                     * sequence, i.e., we continue the search for subsequence in sequence starting at index seqIdx+1 of
//                     * sequence.
//                     */
//                    seqIdx++;
//                }
//            }
//        }
//        return Optional.empty();
//    }
//
//    private Optional<List<PcapPacket>> findSubsequenceInSequence(List<PcapPacket> lowerBound,
//                                                                 List<PcapPacket> upperBound,
//                                                                 List<PcapPacket> sequence,
//                                                                 Conversation.Direction[] subsequenceDirections,
//                                                                 Conversation.Direction[] sequenceDirections) {
//        // Just do the checks for either lower or upper bound!
//        // TODO: For now we use just the lower bound
//        if (sequence.size() < lowerBound.size()) {
//            // If subsequence is longer, it cannot be contained in sequence.
//            return Optional.empty();
//        }
//        if (isTlsSequence(lowerBound) != isTlsSequence(sequence)) {
//            // We consider it a mismatch if one is a TLS application data sequence and the other is not.
//            return Optional.empty();
//        }
//        // If packet directions have not been precomputed by calling code, we need to construct them.
//        if (subsequenceDirections == null) {
//            subsequenceDirections = getPacketDirections(lowerBound, mRouterWanIp);
//        }
//        if (sequenceDirections == null) {
//            sequenceDirections = getPacketDirections(sequence, mRouterWanIp);
//        }
//        int subseqIdx = 0;
//        int seqIdx = 0;
//        while (subseqIdx < lowerBound.size() && seqIdx < sequence.size()) {
//            // TODO: ONLY MATCH PACKET DIRECTIONS
//            if (subsequenceDirections[subseqIdx] == sequenceDirections[seqIdx]) {
//                // A match; advance both indices to consider next packet in subsequence vs. next packet in sequence.
//                subseqIdx++;
//                seqIdx++;
//                if (subseqIdx == lowerBound.size()) {
//                    // We managed to match the entire subsequence in sequence.
//                    // Return the sublist of sequence that matches subsequence.
//                    /*
//                     * TODO:
//                     * ASSUMES THE BACKING LIST (i.e., 'sequence') IS _NOT_ STRUCTURALLY MODIFIED, hence may not work
//                     * for live traces!
//                     */
//                    // TODO: ALSO CHECK TIMING CONSTRAINT
//                    PcapPacket firstPacket = sequence.get(seqIdx - lowerBound.size());
//                    PcapPacket lastPacket = sequence.get(seqIdx);
//                    if (!lastPacket.getTimestamp().isAfter(firstPacket.getTimestamp().plusMillis(mInclusionTimeMillis))) {
//                        return Optional.of(sequence.subList(seqIdx - lowerBound.size(), seqIdx));
//                    }
//                }
//            } else {
//                // Mismatch.
//                if (subseqIdx > 0) {
//                    /*
//                     * If we managed to match parts of subsequence, we restart the search for subsequence in sequence at
//                     * the index of sequence where the current mismatch occurred. I.e., we must reset subseqIdx, but
//                     * leave seqIdx untouched.
//                     */
//                    subseqIdx = 0;
//                } else {
//                    /*
//                     * First packet of subsequence didn't match packet at seqIdx of sequence, so we move forward in
//                     * sequence, i.e., we continue the search for subsequence in sequence starting at index seqIdx+1 of
//                     * sequence.
//                     */
//                    seqIdx++;
//                }
//            }
//        }
//        return Optional.empty();
//    }

    /**
     * Given a cluster, produces a pruned version of that cluster. In the pruned version, there are no duplicate cluster
     * members. Two cluster members are considered identical if their packets lengths and packet directions are
     * identical. The resulting pruned cluster is unmodifiable (this applies to both the outermost list as well as the
     * nested lists) in order to preserve its integrity when exposed to external code (e.g., through
     * {@link #getCluster()}).
     *
     * @param cluster A cluster to prune.
     * @return The resulting pruned cluster.
     */
    @Override
    protected List<List<PcapPacket>> pruneCluster(List<List<PcapPacket>> cluster) {
        List<List<PcapPacket>> prunedCluster = new ArrayList<>();
        for (List<PcapPacket> originalClusterSeq : cluster) {
            boolean alreadyPresent = false;
            for (List<PcapPacket> prunedClusterSeq : prunedCluster) {
                Optional<List<PcapPacket>> duplicate = findSubsequenceInSequence(originalClusterSeq, prunedClusterSeq,
                        mClusterMemberDirections, mClusterMemberDirections);
                if (duplicate.isPresent()) {
                    alreadyPresent = true;
                    break;
                }
            }
            if (!alreadyPresent) {
                prunedCluster.add(Collections.unmodifiableList(originalClusterSeq));
            }
        }
        return Collections.unmodifiableList(prunedCluster);
    }

    /**
     * Given a {@code List<PcapPacket>}, generate a {@code Conversation.Direction[]} such that each entry in the
     * resulting {@code Conversation.Direction[]} specifies the direction of the {@link PcapPacket} at the corresponding
     * index in the input list.
     * @param packets The list of packets for which to construct a corresponding array of packet directions.
     * @param routerWanIp The IP of the router's WAN port. This is used for determining the direction of packets when
     *                    the traffic is captured just outside the local network (at the ISP side of the router). Set to
     *                    {@code null} if {@code packets} stem from traffic captured within the local network.
     * @return A {@code Conversation.Direction[]} specifying the direction of the {@link PcapPacket} at the
     *         corresponding index in {@code packets}.
     */
    private static Conversation.Direction[] getPacketDirections(List<PcapPacket> packets, String routerWanIp) {
        Conversation.Direction[] directions = new Conversation.Direction[packets.size()];
        for (int i = 0; i < packets.size(); i++) {
            PcapPacket pkt = packets.get(i);
            if (getSourceIp(pkt).equals(getDestinationIp(pkt))) {
                // Sanity check: we shouldn't be processing loopback traffic
                throw new AssertionError("loopback traffic detected");
            }
            if (isSrcIpLocal(pkt) || getSourceIp(pkt).equals(routerWanIp)) {
                directions[i] = Conversation.Direction.CLIENT_TO_SERVER;
            } else if (isDstIpLocal(pkt) || getDestinationIp(pkt).equals(routerWanIp)) {
                directions[i] = Conversation.Direction.SERVER_TO_CLIENT;
            } else {
                //throw new IllegalArgumentException("no local IP or router WAN port IP found, can't detect direction");
            }
        }
        return directions;
    }

}
