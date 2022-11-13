package edu.uci.iotproject.trafficreassembly.layer2;

import org.pcap4j.core.PcapPacket;

/**
 * Interface for observing a {@link Layer2Flow}.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public interface Layer2FlowObserver {

    /**
     * Invoked when a new packet is added to the observed flow.
     * @param flow The observed flow.
     * @param newPacket The packet that was added to the flow.
     */
    void onNewPacket(Layer2Flow flow, PcapPacket newPacket);
}
