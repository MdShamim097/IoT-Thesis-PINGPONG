package edu.uci.iotproject.trafficreassembly.layer2;

import org.pcap4j.core.PcapPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.util.MacAddress;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Models a layer 2 flow: groups packets exchanged between two specific endpoints (MAC addresses).
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class Layer2Flow {

    /**
     * The first endpoint of this layer 2 flow.
     */
    private final MacAddress mEndpoint1;

    /**
     * The second endpoint of this layer 2 flow.
     */
    private final MacAddress mEndpoint2;

    /**
     * Clients observing for changes to this layer 2 flow.
     */
    private final List<Layer2FlowObserver> mFlowObservers = new ArrayList<>();

    public Layer2Flow(MacAddress endpoint1, MacAddress endpoint2) {
        mEndpoint1 = endpoint1;
        mEndpoint2 = endpoint2;
    }

    /**
     * Get the first endpoint of this flow.
     * @return the first endpoint of this flow.
     */
    public MacAddress getEndpoint1() {
        return mEndpoint1;
    }

    /**
     * Get the second endpoint of this flow.
     * @return the second endpoint of this flow.
     */
    public MacAddress getEndpoint2() {
        return mEndpoint2;
    }

    /**
     * Register as an observer of this flow.
     * @param observer The client that is to be notified whenever this flow changes (has new packets added).
     */
    public void addFlowObserver(Layer2FlowObserver observer) {
        mFlowObservers.add(observer);
    }

    /**
     * Deregister as an observer of this flow.
     * @param observer The client that no longer wishes to be notified whenever this flow changes.
     */
    public void removeFlowObserver(Layer2FlowObserver observer) {
        mFlowObservers.remove(observer);
    }

    /**
     * The packets in the flow.
     */
    private final List<PcapPacket> mPackets = new ArrayList<>();

    /**
     * Add a packet to this flow.
     * @param packet The packet that is to be added to the flow.
     */
    public void addPacket(PcapPacket packet) {
        verifyAddresses(packet);
        mPackets.add(packet);
        // Notify flow observers of the new packet
        mFlowObservers.forEach(o -> o.onNewPacket(this, packet));
    }

    /**
     * Get the packets pertaining to this flow.
     * @return The packets pertaining to this flow.
     */
    public List<PcapPacket> getPackets() {
        return Collections.unmodifiableList(mPackets);
    }

    /**
     * Verify that a packet pertains to this flow.
     * @param packet The packet that is to be verified.
     */
    private void verifyAddresses(PcapPacket packet) {
        EthernetPacket ethPkt = packet.get(EthernetPacket.class);
        MacAddress srcAddr = ethPkt.getHeader().getSrcAddr();
        MacAddress dstAddr = ethPkt.getHeader().getDstAddr();
        if ((mEndpoint1.equals(srcAddr) && mEndpoint2.equals(dstAddr)) ||
                (mEndpoint1.equals(dstAddr) && mEndpoint2.equals(srcAddr))) {
            // All is good.
            return;
        }
        // TODO: Comment this out for VPN experiments
        //throw new IllegalArgumentException("Mismatch in MACs: packet does not pertain to this flow");
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + String.format(" with mEndpoint1=%s and mEndpoint2=%s", mEndpoint1, mEndpoint2);
    }
}
