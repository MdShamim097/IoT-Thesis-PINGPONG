package edu.uci.iotproject.analysis;

import edu.uci.iotproject.DnsMap;
import edu.uci.iotproject.util.PcapPacketUtils;
import org.apache.commons.math3.stat.clustering.Clusterable;
import org.pcap4j.core.PcapPacket;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static edu.uci.iotproject.util.PcapPacketUtils.getSourceIp;

/**
 * <p>
 *     A simple wrapper for holding a pair of packets (e.g., a request and associated reply packet).
 * </p>
 *
 * <b>Note:</b> we use the deprecated version
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class PcapPacketPair implements Clusterable<PcapPacketPair> {

    /**
     * If {@code true}, {@link #distanceFrom(PcapPacketPair)} will only consider if the sources of the two packets in
     * the {@link PcapPacketPair}s being compared match in terms of whether the IP is a local or a remote IP. It will
     * <em>not</em> check if the IPs/hostnames are actually the same. Set to {@code false} to make the comparison more
     * strict, i.e., to enforce the requirement that the respective IPs (or hostnames) in the packets of the two
     * {@link PcapPacketPair}s must be identical.
     */
    private static final boolean SIMPLIFIED_SOURCE_COMPARISON = true;

    private final PcapPacket mFirst;

    private final Optional<PcapPacket> mSecond;

    /**
     * IP to hostname mappings.
     * Allows for grouping packets with different source IPs that map to the same hostname into one cluster.
     */
    private DnsMap mDnsMap; // TODO implement and invoke setter

    public PcapPacketPair(PcapPacket first, PcapPacket second) {
        mFirst = first;
        mSecond = Optional.ofNullable(second);
    }

    public PcapPacket getFirst() { return mFirst; }

    public boolean isFirstClient() {
        String firstIp = PcapPacketUtils.getSourceIp(mFirst);
        InetAddress ia = null;
        try {
            ia = InetAddress.getByName(firstIp);
        } catch (UnknownHostException ex) {
            ex.printStackTrace();
        }
        return ia.isSiteLocalAddress();
    }

    public Optional<PcapPacket> getSecond() { return mSecond; }

    public boolean isSecondClient() {
        // Return the value of the second source if it is not null
        if (mSecond.isPresent()) {
            String secondIp = PcapPacketUtils.getSourceIp(mSecond.get());
            InetAddress ia = null;
            try {
                ia = InetAddress.getByName(secondIp);
            } catch (UnknownHostException ex) {
                ex.printStackTrace();
            }
            return ia.isSiteLocalAddress();
        } else {
            // When it is null, we always return the opposite of the first source's status
            return !isFirstClient();
        }
    }

    /**
     * Get the {@link DnsMap} that is queried for hostnames mappings when performing IP/hostname-sensitive clustering.
     * @return the {@link DnsMap} that is queried for hostnames mappings when performing IP/hostname-sensitive clustering.
     */
    public DnsMap getDnsMap() {
        return mDnsMap;
    }

    /**
     * Set the {@link DnsMap} to be queried for hostnames mappings when performing IP/hostname-sensitive clustering.
     * @param dnsMap a {@code DnsMap} to be queried for hostnames mappings when performing IP/hostname-sensitive clustering.
     */
    public void setDnsMap(final DnsMap dnsMap) {
        mDnsMap = dnsMap;
    }

    @Override
    public String toString() {
        return String.format("%d, %s",
                getFirst().getOriginalLength(),
                getSecond().map(pkt -> Integer.toString(pkt.getOriginalLength())).orElse("null"));
    }

    // =================================================================================================================
    // Begin implementation of org.apache.commons.math3.stat.clustering.Clusterable interface
    @Override
    public double distanceFrom(PcapPacketPair that) {
        if (SIMPLIFIED_SOURCE_COMPARISON) {
            // Direction of packets in terms of client-to-server or server-to-client must match, but we don't care about
            // IPs and hostnames
            if (this.isFirstClient() != that.isFirstClient() || this.isSecondClient() != that.isSecondClient()) {
                // Distance is maximal if mismatch in direction of packets
                return Double.MAX_VALUE;
            }
        } else {
            // Strict mode enabled: IPs/hostnames must match!
            // Extract src ips of both packets of each pair.
            String thisSrc1 = getSourceIp(this.getFirst());
            String thisSrc2 = this.getSecond().map(pp -> getSourceIp(pp)).orElse("");
            String thatSrc1 = getSourceIp(that.getFirst());
            String thatSrc2 = that.getSecond().map(pp -> getSourceIp(pp)).orElse("");

            // Replace IPs with hostnames if possible.
            thisSrc1 = mapToHostname(thisSrc1);
            thisSrc2 = mapToHostname(thisSrc2);
            thatSrc1 = mapToHostname(thatSrc1);
            thatSrc2 = mapToHostname(thatSrc2);

            if(!thisSrc1.equals(thatSrc1) || !thisSrc2.equals(thatSrc2)) {
                // Distance is maximal if sources differ.
                return Double.MAX_VALUE;
            }
        }

        // If the sources match, the distance is the Euclidean distance between each pair of packet lengths.
        int thisLen1 = this.getFirst().getOriginalLength();
        // TODO should discard pairs w/o second packet from clustering; replace below with getSecond().get() when done.
        int thisLen2 = this.getSecond().map(pp -> pp.getOriginalLength()).orElse(0);
        int thatLen1 = that.getFirst().getOriginalLength();
        // TODO should discard pairs w/o second packet from clustering; replace below with getSecond().get() when done.
        int thatLen2 = that.getSecond().map(pp -> pp.getOriginalLength()).orElse(0);
        return Math.sqrt(
                Math.pow(thisLen1 - thatLen1, 2) +
                        Math.pow(thisLen2 - thatLen2, 2)
        );
    }

    @Override
    public PcapPacketPair centroidOf(Collection<PcapPacketPair> p) {
        // No notion of centroid in DBSCAN
        throw new UnsupportedOperationException("Not implemented; no notion of a centroid in DBSCAN.");
    }
    // End implementation of org.apache.commons.math3.stat.clustering.Clusterable interface
    // =================================================================================================================

    private String mapToHostname(String ip) {
        Set<String> hostnames = mDnsMap.getHostnamesForIp(ip);
        if (hostnames != null && hostnames.size() > 0) {
            // append hostnames back-to-back separated by a delimiter if more than one item in set
            // note: use sorted() to ensure that output remains consistent (as Set has no internal ordering of elements)
            String result = hostnames.stream().sorted().collect(Collectors.joining(" "));
            if (hostnames.size() > 1) {
                // One IP can map to multiple hostnames, although that is rare. For now just raise a warning.
                String warningStr = String.format(
                        "%s.mapToHostname(): encountered an IP (%s) that maps to multiple hostnames (%s)",
                        getClass().getSimpleName(), ip, result);
                System.err.println(warningStr);
            }
            return result;
        }
        // If unable to map to a hostname, return ip for ease of use; caller can overwrite input value, defaulting to
        // the original value if no mapping is found:
        // String src = "<some-ip>";
        // src = mapToHostname(src); // src is now either a hostname or the original ip.
        return ip;
    }

}
