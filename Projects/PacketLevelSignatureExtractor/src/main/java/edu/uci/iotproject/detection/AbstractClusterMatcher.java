package edu.uci.iotproject.detection;

import org.pcap4j.core.PcapPacket;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Base class for classes that search a traffic trace for sequences of packets that "belong to" a given cluster (in
 * other words, classes that attempt to classify traffic as pertaining to a given cluster).
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
abstract public class AbstractClusterMatcher {

    /**
     * The cluster that describes the sequence of packets that this {@link AbstractClusterMatcher} is trying to detect
     * in the observed traffic.
     */
    protected final List<List<PcapPacket>> mCluster;

    /**
     * Observers registered for callbacks from this {@link AbstractClusterMatcher}.
     */
    protected final List<ClusterMatcherObserver> mObservers;

    protected AbstractClusterMatcher(List<List<PcapPacket>> cluster, boolean isRangeBased) {
        // ===================== PRECONDITION SECTION =====================
        cluster = Objects.requireNonNull(cluster, "cluster cannot be null");
        if (cluster.isEmpty() || cluster.stream().anyMatch(inner -> inner.isEmpty())) {
            throw new IllegalArgumentException("cluster is empty (or contains an empty inner List)");
        }
        for (List<PcapPacket> clusterMember : cluster) {
            if (clusterMember.size() != cluster.get(0).size()) {
                throw new IllegalArgumentException("All sequences in cluster must contain the same number of packets");
            }
        }
        // ================================================================
        // Let the subclass prune the provided cluster---only if it is not range-based
        if (!isRangeBased) {
            mCluster = pruneCluster(cluster);
        } else {
            mCluster = cluster;
        }
        mObservers = new ArrayList<>();
    }

    /**
     * Register for callbacks from this cluster matcher.
     * @param observer The target of the callbacks.
     */
    public final void addObserver(ClusterMatcherObserver observer) {
        mObservers.add(observer);
    }

    /**
     * Deregister for callbacks from this cluster matcher.
     * @param observer The callback target that is to be deregistered.
     */
    public final void removeObserver(ClusterMatcherObserver observer) {
        mObservers.remove(observer);
    }

    /**
     * Allows subclasses to specify how to prune the input cluster provided to the constructor.
     * @param cluster The input cluster provided to the constructor.
     * @return The pruned cluster to use in place of the input cluster.
     */
    abstract protected List<List<PcapPacket>> pruneCluster(List<List<PcapPacket>> cluster);

    // TODO: move Direction outside Conversation so that this is less confusing.
//    abstract protected Conversation.Direction[] getPacketDirections(List<PcapPacket> packets);

}
