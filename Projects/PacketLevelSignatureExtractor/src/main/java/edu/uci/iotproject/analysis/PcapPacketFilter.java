package edu.uci.iotproject.analysis;

import org.pcap4j.core.PcapPacket;

/**
 * TODO add class documentation.
 *
 * @author Janus Varmarken
 */
public interface PcapPacketFilter {

    boolean shouldIncludePacket(PcapPacket packet);

}
