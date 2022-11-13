package edu.uci.iotproject.detection;

import org.pcap4j.core.PcapPacket;

import java.util.List;

/**
 * Interface used by client code to register for receiving a notification whenever an {@link AbstractClusterMatcher}
 * detects traffic that matches an element of its associated cluster.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public interface ClusterMatcherObserver {

    /**
     * Callback that is invoked by an {@link AbstractClusterMatcher} whenever it detects traffic that matches an element
     * of its associated cluster.
     *
     * @param clusterMatcher The {@link AbstractClusterMatcher} that detected a match (i.e., classified traffic as
     *                       pertaining to its associated cluster).
     * @param match The traffic that was deemed to match the cluster associated with {@code clusterMatcher}.
     */
    void onMatch(AbstractClusterMatcher clusterMatcher, List<PcapPacket> match);

}
