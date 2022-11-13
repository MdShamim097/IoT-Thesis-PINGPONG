package edu.uci.iotproject.detection.layer2;

import edu.uci.iotproject.analysis.TriggerTrafficExtractor;
import edu.uci.iotproject.util.PcapPacketUtils;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.util.MacAddress;

import java.util.ArrayList;
import java.util.List;

/**
 * Attempts to detect the presence of a specific packet sequence in the set of packets provided through multiple calls
 * to {@link #matchPacket(PcapPacket)}, considering only layer 2 information. This class has the same flavor as the
 * {@link Layer2SequenceMatcher} class.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class Layer2RangeMatcher extends Layer2AbstractMatcher {
    /**
     * The range this {@link Layer2RangeMatcher} is searching for.
     */
    private final List<PcapPacket> mLowerBound;
    private final List<PcapPacket> mUpperBound;
    private final double mEps;
    private int mInclusionTimeMillis;
    private int mSkippedPackets;

    /**
     * Create a {@code Layer2RangeMatcher}.
     * @param lowerBound The lower bound of the sequence to match against (search for).
     * @param upperBound The upper bound of the sequence to match against (search for).
     * @param eps The epsilon value used in the DBSCAN algorithm.
     * @param trainingRouterWlanMac The training router's WLAN MAC (used for determining the direction of packets).
     * @param routerWlanMac The target trace router's WLAN MAC (used for determining the direction of packets).
     */
    public Layer2RangeMatcher(List<PcapPacket> lowerBound, List<PcapPacket> upperBound,
                              int inclusionTimeMillis, double eps, String trainingRouterWlanMac, String routerWlanMac) {
        // TODO: Just use the lower bound since both lower and upper bounds' packets essentially have the same direction
        // TODO: for the same position in the array. Both arrays also have the same length.
        super(lowerBound, trainingRouterWlanMac, routerWlanMac);
        mLowerBound = lowerBound;
        mUpperBound = upperBound;
        mEps = eps;
        mInclusionTimeMillis =
                inclusionTimeMillis == 0 ? TriggerTrafficExtractor.INCLUSION_WINDOW_MILLIS : inclusionTimeMillis;
        mSkippedPackets = 0;
    }

    /**
     * Attempt to advance this {@code Layer2RangeMatcher} by matching {@code packet} against the packet that this
     * {@code Layer2RangeMatcher} expects as the next packet of the sequence it is searching for.
     * @param packet
     * @return {@code true} if this {@code Layer2SequenceMatcher} could advance by adding {@code packet} to its set of
     *         matched packets, {@code false} otherwise.
     */
    public boolean matchPacket(PcapPacket packet) {
        if (getMatchedPacketsCount() == getTargetSequencePacketCount()) {
            // We already matched the entire sequence, so we can't match any more packets.
            return false;
        }

        // Verify that new packet pertains to same flow as previously matched packets, if any.
        if (getMatchedPacketsCount() > 0) {
            MacAddress pktSrc = PcapPacketUtils.getEthSrcAddr(packet);
            MacAddress pktDst = PcapPacketUtils.getEthDstAddr(packet);
            MacAddress earlierPktSrc = PcapPacketUtils.getEthSrcAddr(mMatchedPackets.get(0));
            MacAddress earlierPktDst = PcapPacketUtils.getEthDstAddr(mMatchedPackets.get(0));
            if (!(pktSrc.equals(earlierPktSrc) && pktDst.equals(earlierPktDst) ||
                    pktSrc.equals(earlierPktDst) && pktDst.equals(earlierPktSrc))) {
                return false;
            }
        }

        // Get representative of the packet we expect to match next.
        PcapPacket expectedLowerBound = mLowerBound.get(mMatchedPackets.size());
        PcapPacket expectedUpperBound = mUpperBound.get(mMatchedPackets.size());
        int lowerBound = expectedLowerBound.getOriginalLength();
        int upperBound = expectedUpperBound.getOriginalLength();
        // Do strict matching if the lower and upper bounds are the same length
        // Do range matching with eps otherwise
        if (lowerBound != upperBound) {
            lowerBound = lowerBound - (int) mEps;
            upperBound = upperBound + (int) mEps;
        }
        // First verify if the received packet has the length we're looking for (the length should be within the range).
        if (lowerBound <= packet.getOriginalLength() && packet.getOriginalLength() <= upperBound){
            // If this is the first packet, we only need to verify that its length is correct. Time constraints are
            // obviously satisfied as there are no previous packets. Furthermore, direction matches by definition as we
            // don't know the MAC of the device (or phone) in advance, so we can't enforce a rule saying "first packet
            // must originate from this particular MAC".
            if (getMatchedPacketsCount() == 0) {
                // Store packet as matched and advance.
                mMatchedPackets.add(packet);
                return true;
            }
            // Check if direction of packet matches expected direction.
            boolean actualDirection = getPacketDirection(mMatchedPackets.get(getMatchedPacketsCount()-1),
                    mPacketDirections[getMatchedPacketsCount()-1], packet);
            boolean expectedDirection = mPacketDirections[getMatchedPacketsCount()];
            if (actualDirection != expectedDirection) {
                return false;
            }
            // Next apply timing constraints:
            // 1) to be a match, the packet must have a later timestamp than any other packet currently matched
            // 2) does adding the packet cause the max allowed time between first packet and last packet to be exceeded?
            if (!packet.getTimestamp().isAfter(mMatchedPackets.get(getMatchedPacketsCount()-1).getTimestamp())) {
                return false;
            }
            if (packet.getTimestamp().isAfter(mMatchedPackets.get(0).getTimestamp().
                    plusMillis(mInclusionTimeMillis))) {
                return false;
            }
            // If we made it here, it means that this packet has the expected length, direction, and obeys the timing
            // constraints, so we store it and advance.zzzz
            mMatchedPackets.add(packet);
            if (mMatchedPackets.size() == mLowerBound.size()) {
                // TODO report (to observers?) that we are done?
            }
            return true;
        }
        return false;
    }

    public int getTargetSequencePacketCount() {
        return mLowerBound.size();
    }

    public List<PcapPacket> getTargetLowerBound() {
        return mLowerBound;
    }

    public List<PcapPacket> getTargetUpperBound() {
        return mUpperBound;
    }
}
