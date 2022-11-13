package edu.uci.iotproject.trafficreassembly.layer3;

import org.pcap4j.core.PcapPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;

/**
 * Groups a FIN packet and its corresponding ACK packet. <b>Immutable and thread safe</b>.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class FinAckPair {

    private final PcapPacket mFinPacket;
    private final PcapPacket mCorrespondingAckPacket;

    /**
     * Constructs a {@code FinAckPair} given a FIN packet.
     * The corresponding ACK packet field is set to {@code null}.
     * @param finPacket A FIN packet.
     */
    public FinAckPair(PcapPacket finPacket) {
        if (!finPacket.get(TcpPacket.class).getHeader().getFin()) {
            throw new IllegalArgumentException("not a FIN packet");
        }
        mFinPacket = finPacket;
        mCorrespondingAckPacket = null;
    }

    /**
     * Constructs a {@code FinAckPair} given a FIN and an ACK packet.
     * @param finPacket A FIN packet.
     * @param correspondingAckPacket The ACK packet corresponding to {@code finPacket}.
     */
    public FinAckPair(PcapPacket finPacket, PcapPacket correspondingAckPacket) {
        // Enforce class invariant, i.e. that the FIN and ACK are related.
        // Note that it is indirectly checked whether finPacket is indeed a FIN packet
        // as isCorrespondingAckPacket calls the single parameter constructor.
        if (!FinAckPair.isCorrespondingAckPacket(finPacket, correspondingAckPacket)) {
            throw new IllegalArgumentException("FIN and ACK not related");
        }
        mFinPacket = finPacket;
        mCorrespondingAckPacket = correspondingAckPacket;
    }

    /**
     * Get the FIN packet of this pair.
     * @return the FIN packet of this pair.
     */
    public PcapPacket getFinPacket() {
        return mFinPacket;
    }

    /**
     * Get the corresponding ACK packet of this pair, if any.
     * @return the corresponding ACK packet of this pair, if any.
     */
    public PcapPacket getCorrespondingAckPacket() {
        return mCorrespondingAckPacket;
    }

    /**
     * Was the FIN in this {@code FinAckPair} acknowledged?
     *
     * @return {@code true} if the corresponding ACK has been set in this {@code FinAckPair}.
     */
    public boolean isAcknowledged() {
        return mFinPacket != null && mCorrespondingAckPacket != null;
    }

    /**
     * Checks if a given packet is an ACK corresponding to the FIN packet in this {@code FinAckPair}.
     * @return {@code true} if {@code packet} is an ACK that corresponds to the FIN in this pair, {@code false} otherwise.
     */
    public boolean isCorrespondingAckPacket(PcapPacket packet) {
        IpV4Packet inputIpPacket = packet.get(IpV4Packet.class);
        TcpPacket inputTcpPacket = packet.get(TcpPacket.class);
        if (inputIpPacket == null || inputTcpPacket == null || !inputTcpPacket.getHeader().getAck()) {
            return false;
        }

        IpV4Packet finIpPacket = mFinPacket.get(IpV4Packet.class);
        TcpPacket finTcpPacket = mFinPacket.get(TcpPacket.class);

        // Extract (srcIp:port,dstIp:port) for input and member (FIN) packets.
        String inputPacketIpSrc = inputIpPacket.getHeader().getSrcAddr().getHostAddress();
        String inputPacketIpDst = inputIpPacket.getHeader().getDstAddr().getHostAddress();
        int inputPacketPortSrc = inputTcpPacket.getHeader().getSrcPort().valueAsInt();
        int inputPacketPortDst = inputTcpPacket.getHeader().getDstPort().valueAsInt();
        String finPacketIpSrc = finIpPacket.getHeader().getSrcAddr().getHostAddress();
        String finPacketIpDst = finIpPacket.getHeader().getDstAddr().getHostAddress();
        int finPacketPortSrc = finTcpPacket.getHeader().getSrcPort().valueAsInt();
        int finPacketPortDst = finTcpPacket.getHeader().getDstPort().valueAsInt();

        // For the two packets to be related, the dst of one must be the src of the other.
        // Split into multiple if statements for readability. First check IP fields, then ports.
        if (!(inputPacketIpDst.equals(finPacketIpSrc) && finPacketIpDst.equals(inputPacketIpSrc))) {
            return false;
        }
        if (!(inputPacketPortDst == finPacketPortSrc && finPacketPortDst == inputPacketPortSrc)) {
            return false;
        }

        // Packets are (most likely) related (part of same conversation/stream).
        // Now all that is left for us to check is if the sequence numbers match.
        // Note: recall that the FIN packet advances the seq numbers by 1,
        // so the ACK number will be one larger than the seq. number in the FIN packet.
        return inputTcpPacket.getHeader().getAcknowledgmentNumber() == finTcpPacket.getHeader().getSequenceNumber() + 1;
    }

    /**
     * Static method to check if two given packets are a FIN and the corresponding ACK packet.
     * The purpose of this method is a workaround to enforce the class invariant in the two parameter constructor.
     * Specifically, the following should be avoided:
     * <pre>
     *     public FinAckPair(PcapPacket finPacket, PcapPacket correspondingAckPacket) {
     *         mFinPacket = finPacket;
     *         // Below line is considered bad practice as the object has not been fully initialized at this stage.
     *         if (!this.isCorrespondingAckPacket(correspondingAckPacket)) {
     *             // ... throw exception
     *         }
     *     }
     * </pre>
     * @param finPacket The FIN packet.
     * @param ackPacket The ACK packet that is to be checked if it corresponds to the given FIN packet.
     * @return {@code true} if the ACK corresponds to the FIN, {@code false} otherwise.
     */
    private static boolean isCorrespondingAckPacket(PcapPacket finPacket, PcapPacket ackPacket) {
        FinAckPair tmp = new FinAckPair(finPacket);
        return tmp.isCorrespondingAckPacket(ackPacket);
    }

}
