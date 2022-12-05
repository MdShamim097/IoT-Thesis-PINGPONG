package edu.uci.iotproject.detection.layer2;

import edu.uci.iotproject.analysis.TriggerTrafficExtractor;
import edu.uci.iotproject.trafficreassembly.layer2.Layer2FlowReassembler;
import edu.uci.iotproject.trafficreassembly.layer2.Layer2Flow;
import edu.uci.iotproject.trafficreassembly.layer2.Layer2FlowReassemblerObserver;
import edu.uci.iotproject.detection.AbstractClusterMatcher;
import edu.uci.iotproject.trafficreassembly.layer2.Layer2FlowObserver;
import org.pcap4j.core.*;

import java.util.*;
import java.util.function.Function;

/**
 * Attempts to detect members of a cluster (packet sequence mutations) in layer 2 flows.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class Layer2ClusterMatcher extends AbstractClusterMatcher implements Layer2FlowReassemblerObserver, Layer2FlowObserver {

    /**
     * Maps from a flow to a table of {@link Layer2SequenceMatcher}s for that particular flow. The table {@code t} is
     * structured such that {@code t[i][j]} is a {@link Layer2SequenceMatcher} that attempts to match member {@code i}
     * of {@link #mCluster} and has so far matched {@code j} packets of that particular sequence.
     */
    private final Map<Layer2Flow, Layer2SequenceMatcher[][]> mPerFlowSeqMatchers = new HashMap<>();
    private final Map<Layer2Flow, List<Layer2RangeMatcher>> mPerFlowRangeMatcher = new HashMap<>();

    private final Function<Layer2Flow, Boolean> mFlowFilter;

    /**
     * Specifying range-based instead of conservative exact matching.
     */
    private final boolean mRangeBased;

    /**
     * Epsilon value used by the DBSCAN algorithm; it is used again for range-based matching here.
     */
    private final double mEps;

    private int mInclusionTimeMillis;
    private int mInclusionPackets;
    /**
     * Keeping track of maximum number of skipped packets
     */
    private int mMaxSkippedPackets;
    private List<Integer> mSkippedPackets;

    private int mLimitSkippedPackets;

    /**
     * Router's WLAN MAC.
     */
    private String mTrainingRouterWlanMac;
    private String mRouterWlanMac;

    /**
     * Relaxed matching
     */
    private int mDelta;
    private Set<Integer> mPacketSet;

    /**
     * Create a new {@link Layer2ClusterMatcher} that attempts to find occurrences of {@code cluster}'s members.
     * @param cluster The sequence mutations that the new {@link Layer2ClusterMatcher} should search for.
     */
    public Layer2ClusterMatcher(List<List<PcapPacket>> cluster, String trainingRouterWlanMac, String routerWlanMac, int inclusionTimeMillis, //int inclusionPacketNumbers,
                                boolean isRangeBased, double eps, int limitSkippedPackets, int delta, Set<Integer> packetSet) {
        // Consider all flows if no flow filter specified.
        this(cluster, trainingRouterWlanMac, routerWlanMac, flow -> true, inclusionTimeMillis, //inclusionPacketNumbers,
             isRangeBased, eps, limitSkippedPackets, delta, packetSet);
    }

    /**
     * Create a new {@link Layer2ClusterMatcher} that attempts to find occurrences of {@code cluster}'s members.
     * @param cluster The sequence mutations that the new {@link Layer2ClusterMatcher} should search for.
     * @param trainingRouterWlanMac The training router's WLAN MAC (used for determining the direction of packets).
     * @param routerWlanMac The target trace router's WLAN MAC (used for determining the direction of packets).
     * @param flowFilter A filter that defines what {@link Layer2Flow}s the new {@link Layer2ClusterMatcher} should
     *                   search for {@code cluster}'s members in. If {@code flowFilter} returns {@code true}, the flow
     *                   will be included (searched). Note that {@code flowFilter} is only queried once for each flow,
     *                   namely when the {@link Layer2FlowReassembler} notifies the {@link Layer2ClusterMatcher} about
     *                   the new flow. This functionality may for example come in handy when one only wants to search
     *                   for matches in the subset of flows that involves a specific (range of) MAC(s).
     * @param inclusionTimeMillis Packet inclusion time limit for matching.
     * @param isRangeBased The boolean that decides if it is range-based vs. strict matching.
     * @param eps The epsilon value used in the DBSCAN algorithm.
     */
    public Layer2ClusterMatcher(List<List<PcapPacket>> cluster, String trainingRouterWlanMac, String routerWlanMac,
                                Function<Layer2Flow, Boolean> flowFilter, int inclusionTimeMillis, //int inclusionPacketNumbers, 
                                boolean isRangeBased,
                                double eps, int limitSkippedPackets, int delta, Set<Integer> packetSet) {
        super(cluster, isRangeBased);
        mFlowFilter = flowFilter;
        mTrainingRouterWlanMac = trainingRouterWlanMac;
        mRouterWlanMac = routerWlanMac;
        mRangeBased = isRangeBased;
        mEps = eps;
        mInclusionTimeMillis =
                inclusionTimeMillis == 0 ? TriggerTrafficExtractor.INCLUSION_WINDOW_MILLIS : inclusionTimeMillis;
        /*
        mInclusionPackets =
                inclusionPacketNumbers == 0 ? TriggerTrafficExtractor.INCLUSION_NUMBER_OF_PACKETS : inclusionPacketNumbers;
        */
        mMaxSkippedPackets = 0;
        mSkippedPackets = new ArrayList<>();
        // Give integer's MAX_VALUE if -1
        mLimitSkippedPackets = limitSkippedPackets == -1 ? Integer.MAX_VALUE : limitSkippedPackets;
        mDelta = delta;
        mPacketSet = packetSet;
    }

    @Override
    public void onNewPacket(Layer2Flow flow, PcapPacket newPacket) {
        if (mRangeBased) {
            rangeBasedMatching(flow, newPacket);
        } else {
            conservativeMatching(flow, newPacket);
        }
    }

    // TODO: Relaxed matching is applied in conservative matching
    private void conservativeMatching(Layer2Flow flow, PcapPacket newPacket) {
        if (mPerFlowSeqMatchers.get(flow) == null) {
            // If this is the first time we encounter this flow, we need to set up sequence matchers for it.
            // All sequences of the cluster have the same length, so we only need to compute the length of the nested
            // arrays once. We want to make room for a cluster matcher in each state, including the initial empty state
            // but excluding the final "full match" state (as there is no point in keeping a terminated sequence matcher
            // around), so the length of the inner array is simply the sequence length.
            Layer2SequenceMatcher[][] matchers = new Layer2SequenceMatcher[mCluster.size()][mCluster.get(0).size()];
            // Prepare a "state 0" sequence matcher for each sequence variation in the cluster.
            for (int i = 0; i < matchers.length; i++) {
                matchers[i][0] = new Layer2SequenceMatcher(mCluster.get(i), mInclusionTimeMillis, //mInclusionPackets,
                        mTrainingRouterWlanMac,
                        mRouterWlanMac, mDelta, mPacketSet);
            }
            // Associate the new sequence matcher table with the new flow
            mPerFlowSeqMatchers.put(flow, matchers);
        }
        // Fetch table that contains sequence matchers for this flow.
        Layer2SequenceMatcher[][] matchers = mPerFlowSeqMatchers.get(flow);
        // Present the packet to all sequence matchers.
        for (int i = 0; i < matchers.length; i++) {
            // Present packet to the sequence matchers that has advanced the most first. This is to prevent discarding
            // the sequence matchers that have advanced the most in the special case where the searched sequence
            // contains two packets of the same length going in the same direction.
            for (int j = matchers[i].length - 1; j >= 0 ; j--) {
                Layer2SequenceMatcher sm = matchers[i][j];
                if (sm == null) {
                    // There is currently no sequence matcher that has managed to match j packets.
                    continue;
                }
                boolean matched = sm.matchPacket(newPacket);
                if (matched) {
                    if (sm.getMatchedPacketsCount() == sm.getTargetSequencePacketCount()) {
                        // Update maximum skipped packets
                        boolean stillMatch = checkMaxSkippedPackets(flow.getPackets(), sm.getMatchedPackets());
                        if (stillMatch) {
                            // Sequence matcher has a match. Report it to observers.
                            mObservers.forEach(o -> o.onMatch(this, sm.getMatchedPackets()));
                        }
                        // Remove the now terminated sequence matcher.
                        matchers[i][j] = null;
                    } else {
                        // Sequence matcher advanced one step, so move it to its corresponding new position iff the
                        // packet that advanced it has a later timestamp than that of the last matched packet of the
                        // sequence matcher at the new index, if any. In most traces, a small amount of the packets
                        // appear out of order (with regards to their timestamp), which is why this check is required.
                        // Obviously it would not be needed if packets where guaranteed to be processed in timestamp
                        // order here.
                        if (matchers[i][j+1] == null ||
                                newPacket.getTimestamp().isAfter(matchers[i][j+1].getLastPacket().getTimestamp())) {
                            matchers[i][j+1] = sm;
                        }
                    }
                    // We always want to have a sequence matcher in state 0, regardless of if the one that advanced
                    // from state zero completed its matching or if it replaced a different one in state 1 or not.
                    if (sm.getMatchedPacketsCount() == 1) {
                        matchers[i][j] = new Layer2SequenceMatcher(sm.getTargetSequence(), mInclusionTimeMillis, //mInclusionPackets,
                                mTrainingRouterWlanMac, mRouterWlanMac, mDelta, mPacketSet);
                    }
                }
            }
        }
    }

    // Update the maximum number of skipped packets.
    private boolean checkMaxSkippedPackets(List<PcapPacket> flowPackets, List<PcapPacket> matchedPackets) {
        // Count number of skipped packets by looking into
        // the difference of indices of two matched packets.
        boolean stillMatch = true;
        for(int i = 1; i < matchedPackets.size(); ++i) {
            int currIndex = flowPackets.indexOf(matchedPackets.get(i-1));
            int nextIndex = flowPackets.indexOf(matchedPackets.get(i));
            int skippedPackets = nextIndex - currIndex;
            if (mMaxSkippedPackets < skippedPackets) {
                mMaxSkippedPackets = skippedPackets;
            }
            if (mLimitSkippedPackets < skippedPackets) {
                stillMatch = false;
            }
            mSkippedPackets.add(skippedPackets);
        }
        return stillMatch;
    }

    private void rangeBasedMatching(Layer2Flow flow, PcapPacket newPacket) {
        // TODO: For range-based matching, we need to create a new matcher every time we see the first element of
        //  the sequence (between lower and upper bounds).
        if (mPerFlowRangeMatcher.get(flow) == null) {
            // If this is the first time we encounter this flow, we need to set up a list of sequence matchers.
            List<Layer2RangeMatcher> listMatchers = new ArrayList<>();
            // Prepare a "state 0" sequence matcher.
            Layer2RangeMatcher matcher = new Layer2RangeMatcher(mCluster.get(0), mCluster.get(1),
                    mInclusionTimeMillis, //mInclusionPackets,
                    mEps, mTrainingRouterWlanMac, mRouterWlanMac);
            listMatchers.add(matcher);
            // Associate the new sequence matcher table with the new flow.
            mPerFlowRangeMatcher.put(flow, listMatchers);
        }
        // Fetch table that contains sequence matchers for this flow.
        List<Layer2RangeMatcher> listMatchers = mPerFlowRangeMatcher.get(flow);
        // Add a new matcher if all matchers have already advanced to the next stage.
        // We always need a new matcher to match from NO packets.
        boolean addOneArray = true;
        for(Layer2RangeMatcher matcher : listMatchers) {
            if (matcher.getMatchedPacketsCount() == 0) {
                addOneArray = false;
            }
        }
        // Add the new matcher into the list
        if (addOneArray) {
            Layer2RangeMatcher newMatcher = new Layer2RangeMatcher(mCluster.get(0), mCluster.get(1),
                    mInclusionTimeMillis, //mInclusionPackets,
                    mEps, mTrainingRouterWlanMac, mRouterWlanMac);
            listMatchers.add(newMatcher);
        }
        // Present packet to the sequence matchers.
        // Make a shallow copy of the list so that we can clean up the actual list when a matcher is terminated.
        // Otherwise, we would get an exception for changing the list while iterating on it.
        List<Layer2RangeMatcher> listMatchersCopy = new ArrayList<>(listMatchers);
        Layer2RangeMatcher previousMatcher = null;
        for(Layer2RangeMatcher matcher : listMatchersCopy) {
            Layer2RangeMatcher sm = matcher;
            // Check if no packets are matched yet or if there are matched packets, the next packet to be matched
            // has to be later than the last matched packet.
            // In most traces, a small amount of the packets appear out of order (with regards to their timestamp),
            // which is why this check is required.
            // Obviously it would not be needed if packets where guaranteed to be processed in timestamp
            // order here.
            if (sm.getMatchedPacketsCount() == 0 ||
                    newPacket.getTimestamp().isAfter(sm.getLastPacket().getTimestamp())) {
                boolean matched = sm.matchPacket(newPacket);
                if (matched) {
                    // BUG: found on May 29, 2019
                    // We need to remove a previous match if the current match is later in time.
                    // This is done only if we have matched at least 1 packet (we are about to match the second or
                    // later packets) and we match for the same packet position in the signature (check the size!).
                    if (previousMatcher != null && sm.getMatchedPacketsCount() > 1 &&
                            previousMatcher.getMatchedPacketsCount() == sm.getMatchedPacketsCount()) {
                        List<PcapPacket> previouslyMatchedPackets = previousMatcher.getMatchedPackets();
                        List<PcapPacket> currentlyMatchedPackets = sm.getMatchedPackets();
                        // We need to check 1 packet before the last matched packet from the previous matcher.
                        int packetIndexToCheck = (sm.getMatchedPacketsCount() - 1) - 1;
                        if (currentlyMatchedPackets.get(packetIndexToCheck).getTimestamp().
                            isAfter(previouslyMatchedPackets.get(packetIndexToCheck).getTimestamp())) {
                            listMatchers.remove(previousMatcher);
                        }
                    }
                    if (sm.getMatchedPacketsCount() == sm.getTargetSequencePacketCount()) {
                        // Update maximum skipped packets
                        boolean stillMatch = checkMaxSkippedPackets(flow.getPackets(), sm.getMatchedPackets());
                        if (stillMatch) {
                            // Sequence matcher has a match. Report it to observers.
                            mObservers.forEach(o -> o.onMatch(this, sm.getMatchedPackets()));
                        }
                        // Terminate sequence matcher since matching is complete.
                        listMatchers.remove(matcher);
                    }
                    previousMatcher = sm;
                }
            }
        }
    }

    @Override
    protected List<List<PcapPacket>> pruneCluster(List<List<PcapPacket>> cluster) {
        // Note: we assume that all sequences in the input cluster are of the same length and that their packet
        // directions are identical.
        List<List<PcapPacket>> prunedCluster = new ArrayList<>();
        for (List<PcapPacket> originalClusterSeq : cluster) {
            boolean alreadyPresent = prunedCluster.stream().anyMatch(pcPkts -> {
                for (int i = 0; i < pcPkts.size(); i++) {
                    if (pcPkts.get(i).getOriginalLength() != originalClusterSeq.get(i).getOriginalLength()) {
                        return false;
                    }
                }
                return true;
            });
            if (!alreadyPresent) {
                // Add the sequence if not already present in the pruned cluster.
                prunedCluster.add(originalClusterSeq);
            }
        }
        return prunedCluster;
    }

    private static final boolean DEBUG = false;

    @Override
    public void onNewFlow(Layer2FlowReassembler reassembler, Layer2Flow newFlow) {
        // New flow detected. Check if we should consider it when searching for cluster member matches.
        if (mFlowFilter.apply(newFlow)) {
            if (DEBUG) {
                System.out.println(">>> ACCEPTING FLOW: " + newFlow + " <<<");
            }
            // Subscribe to the new flow to get updates whenever a new packet pertaining to the flow is processed.
            newFlow.addFlowObserver(this);
        } else if (DEBUG) {
            System.out.println(">>> IGNORING FLOW: " + newFlow + " <<<");
        }
    }

    /**
      * Return the maximum number of skipped packets.
      */
    public int getMaxSkippedPackets() {
       return mMaxSkippedPackets;
    }

    /**
     * Return the numbers of skipped packets.
     */
    public List<Integer> getSkippedPackets() {
        return mSkippedPackets;
    }
}
