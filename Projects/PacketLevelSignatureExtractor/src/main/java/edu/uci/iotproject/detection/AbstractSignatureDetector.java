package edu.uci.iotproject.detection;

import org.pcap4j.core.PcapPacket;

import java.util.*;

/**
 * TODO add class documentation.
 *
 * @author Janus Varmarken
 */
public abstract class AbstractSignatureDetector implements ClusterMatcherObserver {


    /**
     * The signature that this {@link AbstractSignatureDetector} is searching for.
     */
    private final List<List<List<PcapPacket>>> mSignature;

    /**
     * The {@link AbstractClusterMatcher}s in charge of detecting each individual sequence of packets that together make
     * up the the signature.
     */
    private final List<AbstractClusterMatcher> mClusterMatchers;

    /**
     * For each {@code i} ({@code i >= 0 && i < pendingMatches.length}), {@code pendingMatches[i]} holds the matches
     * found by the {@link AbstractClusterMatcher} at {@code mClusterMatchers.get(i)} that have yet to be "consumed",
     * i.e., have yet to be included in a signature detected by this {@link AbstractSignatureDetector} (a signature can
     * be encompassed of multiple packet sequences occurring shortly after one another on multiple connections).
     */
    private final List<List<PcapPacket>>[] pendingMatches;

    /**
     * Maps an {@link AbstractClusterMatcher} to its corresponding index in {@link #pendingMatches}.
     */
    private final Map<AbstractClusterMatcher, Integer> mClusterMatcherIds;

    public AbstractSignatureDetector(List<List<List<PcapPacket>>> searchedSignature) {
        mSignature = Collections.unmodifiableList(searchedSignature);
        List<AbstractClusterMatcher> clusterMatchers = new ArrayList<>();
        for (List<List<PcapPacket>> cluster : mSignature) {
            AbstractClusterMatcher clusterMatcher = constructClusterMatcher(cluster);
            clusterMatcher.addObserver(this);
            clusterMatchers.add(clusterMatcher);
        }
        mClusterMatchers = Collections.unmodifiableList(clusterMatchers);
        pendingMatches = new List[mClusterMatchers.size()];
        for (int i = 0; i < pendingMatches.length; i++) {
            pendingMatches[i] = new ArrayList<>();
        }
        Map<AbstractClusterMatcher, Integer> clusterMatcherIds = new HashMap<>();
        for (int i = 0; i < mClusterMatchers.size(); i++) {
            clusterMatcherIds.put(mClusterMatchers.get(i), i);
        }
        mClusterMatcherIds = Collections.unmodifiableMap(clusterMatcherIds);
    }

    abstract protected AbstractClusterMatcher constructClusterMatcher(List<List<PcapPacket>> cluster);

    /**
     * Encapsulates a {@code List<PcapPacket>} so as to allow the list to be used as a vertex in a graph while avoiding
     * the expensive {@link AbstractList#equals(Object)} calls when adding vertices to the graph.
     * Using this wrapper makes the incurred {@code equals(Object)} calls delegate to {@link Object#equals(Object)}
     * instead of {@link AbstractList#equals(Object)}. The net effect is a faster implementation, but the graph will not
     * recognize two lists that contain the same items--from a value and not reference point of view--as the same
     * vertex. However, this is fine for our purposes -- in fact restricting it to reference equality seems more
     * appropriate.
     */
    private static class Vertex {
        private final List<PcapPacket> sequence;
        private Vertex(List<PcapPacket> wrappedSequence) {
            sequence = wrappedSequence;
        }
    }

}
