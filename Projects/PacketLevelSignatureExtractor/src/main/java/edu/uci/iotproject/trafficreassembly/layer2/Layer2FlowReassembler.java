package edu.uci.iotproject.trafficreassembly.layer2;

import edu.uci.iotproject.trafficreassembly.layer2.Layer2Flow;
import edu.uci.iotproject.trafficreassembly.layer2.Layer2FlowReassemblerObserver;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.util.MacAddress;

import java.util.*;

/**
 * Reassembles traffic flows at layer 2, i.e., for each combination of hosts, creates a list of packets exchanged
 * between said hosts.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class Layer2FlowReassembler implements PacketListener {

    /**
     * Maps a pair of MAC addresses to the packets exchanged between the two hosts.
     * The key is the concatenation of the two MAC addresses in hex string format, where the lexicographically smaller
     * MAC is at the front of the string.
     */
    private final Map<String, Layer2Flow> mFlows = new HashMap<>();

    private final List<Layer2FlowReassemblerObserver> mObservers = new ArrayList<>();

    private String mVpnClientMacAddress = null;

    public Layer2FlowReassembler() { }

    public Layer2FlowReassembler(String vpnClientMacAddress) {
        mVpnClientMacAddress = vpnClientMacAddress;
    }

    @Override
    public void gotPacket(PcapPacket packet) {
        // TODO: update to 802.11 packet...?
        EthernetPacket ethPkt = packet.get(EthernetPacket.class);

        MacAddress srcAddr = ethPkt.getHeader().getSrcAddr();
        MacAddress dstAddr = ethPkt.getHeader().getDstAddr();

        String key = null;
        if (mVpnClientMacAddress != null) {
            if (srcAddr.toString().equals(mVpnClientMacAddress)) {
                key = srcAddr.toString();
            } else if (dstAddr.toString().equals(mVpnClientMacAddress)) {
                key = dstAddr.toString();
            } else {
                return;
            }
        } else {
            key = keyFromAddresses(srcAddr, dstAddr);
        }
        // Create a new list if this pair of MAC addresses where not previously encountered and add packet to that list,
        // or simply add to an existing list if one is present.
        mFlows.computeIfAbsent(key, k -> {
            Layer2Flow newFlow = new Layer2Flow(srcAddr, dstAddr);
            // Inform observers of the new flow
            mObservers.forEach(o -> o.onNewFlow(this, newFlow));
            return newFlow;
        }).addPacket(packet);
    }

    public void addObserver(Layer2FlowReassemblerObserver observer) {
        mObservers.add(observer);
    }

    public void removeObserver(Layer2FlowReassemblerObserver observer) {
        mObservers.remove(observer);
    }

    /**
     * Get the traffic flow between two local endpoints ({@link MacAddress}es).
     * @param addr1 The first endpoint.
     * @param addr2 The second endpoint
     * @return The traffic exchanged between the two endpoints.
     */
    public Layer2Flow getFlowForAddresses(MacAddress addr1, MacAddress addr2) {
        return mFlows.get(keyFromAddresses(addr1, addr2));
    }

    /**
     * Get all traffic flows, i.e., a traffic flow for each unique pair of endpoints (MAC addresses).
     * @return All traffic flows.
     */
    public Collection<Layer2Flow> getFlows() {
        return mFlows.values();
    }

    /**
     * Given two {@link MacAddress}es, generates the corresponding key string used in {@link #mFlows}.
     * @param addr1 The first address.
     * @param addr2 The second address.
     * @return the key string used in {@link #mFlows} corresponding to the two addresses.
     */
    private String keyFromAddresses(MacAddress addr1, MacAddress addr2) {
        String addr1Str = addr1.toString();
        String addr2Str = addr2.toString();
        return addr1Str.compareTo(addr2Str) < 0 ? addr1Str + addr2Str : addr2Str + addr1Str;
    }
}
