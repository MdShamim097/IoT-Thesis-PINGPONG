package edu.uci.iotproject.trafficreassembly.layer3;

import edu.uci.iotproject.analysis.TcpConversationUtils;
import edu.uci.iotproject.util.PcapPacketUtils;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.*;

/**
 * Models a (TCP) conversation/connection/session/flow (packet's belonging to the same session between a client and a
 * server).
 * Holds a list of {@link PcapPacket}s identified as pertaining to the flow. Note that this list is <em>not</em>
 * considered when determining equality of two {@code Conversation} instances in order to allow for a
 * {@code Conversation} to function as a key in data structures such as {@link java.util.Map} and {@link java.util.Set}.
 * See {@link #equals(Object)} for the definition of equality.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class Conversation {

    /* Begin instance properties */
    /**
     * The IP of the host that is considered the client (i.e. the host that initiates the conversation)
     * in this conversation.
     */
    private final String mClientIp;

    /**
     * The port number used by the host that is considered the client in this conversation.
     */
    private final int mClientPort;

    /**
     * The IP of the host that is considered the server (i.e. is the responder) in this conversation.
     */
    private final String mServerIp;

    /**
     * The port number used by the server in this conversation.
     */
    private final int mServerPort;

    /**
     * The list of packets (with payload) pertaining to this conversation.
     */
    private final List<PcapPacket> mPackets;

    /**
     * If {@link #isTls()} is {@code true}, this list contains the subset of {@link #mPackets} which are TLS Application
     * Data packets.
     */
    private final List<PcapPacket> mTlsApplicationDataPackets;

    /**
     * Contains the sequence numbers used thus far by the host that is considered the <em>client</em> in this
     * {@code Conversation}.
     * Used for filtering out retransmissions.
     */
    private final Set<Integer> mSeqNumbersClient;

    /**
     * Contains the sequence numbers used thus far by the host that is considered the <em>server</em> in this
     * {@code Conversation}.
     * Used for filtering out retransmissions.
     */
    private final Set<Integer> mSeqNumbersSrv;

    /**
     * List of SYN packets pertaining to this conversation.
     */
    private final List<PcapPacket> mSynPackets;

    /**
     * List of pairs FINs and their corresponding ACKs associated with this conversation.
     */
    private final List<FinAckPair> mFinPackets;

    /**
     * List of RST packets associated with this conversation.
     */
    private final List<PcapPacket> mRstPackets;

    /**
     * Boolean to mark the packet as Application Data based on the previous packet that reaches MTU
     */
    private boolean mApplicationData;
    /* End instance properties */

    /**
     * Factory method for creating a {@code Conversation} from a {@link PcapPacket}.
     * @param pcapPacket The {@code PcapPacket} that wraps a TCP segment for which a {@code Conversation} is to be initiated.
     * @param clientIsSrc If {@code true}, the source address and source port found in the IP datagram and TCP segment
     *                    wrapped in the {@code PcapPacket} are regarded as pertaining to the client, and the destination
     *                    address and destination port are regarded as pertaining to the server---and vice versa if set
     *                    to {@code false}.
     * @return A {@code Conversation} initiated with ip:port for client and server according to the direction of the packet.
     */
    public static Conversation fromPcapPacket(PcapPacket pcapPacket, boolean clientIsSrc) {
        IpV4Packet ipPacket = pcapPacket.get(IpV4Packet.class);
        TcpPacket tcpPacket = pcapPacket.get(TcpPacket.class);
        String clientIp = clientIsSrc ? ipPacket.getHeader().getSrcAddr().getHostAddress() :
                ipPacket.getHeader().getDstAddr().getHostAddress();
        String srvIp = clientIsSrc ? ipPacket.getHeader().getDstAddr().getHostAddress() :
                ipPacket.getHeader().getSrcAddr().getHostAddress();
        int clientPort = clientIsSrc ? tcpPacket.getHeader().getSrcPort().valueAsInt() :
                tcpPacket.getHeader().getDstPort().valueAsInt();
        int srvPort = clientIsSrc ? tcpPacket.getHeader().getDstPort().valueAsInt() :
                tcpPacket.getHeader().getSrcPort().valueAsInt();
        return new Conversation(clientIp, clientPort, srvIp, srvPort);
    }

    /**
     * Constructs a new {@code Conversation}.
     * @param clientIp The IP of the host that is considered the client (i.e. the host that initiates the conversation)
     *                 in the conversation.
     * @param clientPort The port number used by the client for the conversation.
     * @param serverIp The IP of the host that is considered the server (i.e. is the responder) in the conversation.
     * @param serverPort The port number used by the server for the conversation.
     */
    public Conversation(String clientIp, int clientPort, String serverIp, int serverPort) {
        this.mClientIp = clientIp;
        this.mClientPort = clientPort;
        this.mServerIp = serverIp;
        this.mServerPort = serverPort;
        this.mPackets = new ArrayList<>();
        this.mTlsApplicationDataPackets = new ArrayList<>();
        this.mSeqNumbersClient = new HashSet<>();
        this.mSeqNumbersSrv = new HashSet<>();
        this.mSynPackets = new ArrayList<>();
        this.mFinPackets = new ArrayList<>();
        this.mRstPackets = new ArrayList<>();
        this.mApplicationData = false;
    }

    /**
     * Add a packet to the list of packets associated with this conversation.
     * @param packet The packet that is to be added to (associated with) this conversation.
     * @param ignoreRetransmissions Boolean value indicating if retransmissions should be ignored.
     *                              If set to {@code true}, {@code packet} will <em>not</em> be added to the
     *                              internal list of packets pertaining to this {@code Conversation}
     *                              <em>iff</em> the sequence number of {@code packet} was already
     *                              seen in a previous packet.
     */
    public void addPacket(PcapPacket packet, boolean ignoreRetransmissions) {
        // Precondition: verify that packet does indeed pertain to conversation.
        onAddPrecondition(packet);
        if (ignoreRetransmissions && isRetransmission(packet)) {
            // Packet is a retransmission. Ignore it.
            return;
        }
        // Select direction-dependent set of sequence numbers seen so far and update it with sequence number of new packet.
        addSeqNumber(packet);
        // Finally add packet to list of packets pertaining to this conversation.
        mPackets.add(packet);
        // Preserve order of packets in list: sort according to timestamp.
        if (mPackets.size() > 1 &&
                mPackets.get(mPackets.size()-1).getTimestamp().isBefore(mPackets.get(mPackets.size()-2).getTimestamp())) {
            Collections.sort(mPackets, (o1, o2) -> {
                if (o1.getTimestamp().isBefore(o2.getTimestamp())) { return -1; }
                else if (o2.getTimestamp().isBefore(o1.getTimestamp())) { return 1; }
                else { return 0; }
            });
        }
        // If TLS, inspect packet to see if it's a TLS Application Data packet, and if so add it to the list of TLS
        // Application Data packets.
        if (isTls()) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            Packet tcpPayload = tcpPacket.getPayload();
            if (tcpPayload == null) {
                return;
            }
            byte[] rawPayload = tcpPayload.getRawData();
            // The SSL record header is at the front of the payload and is 5 bytes long.
            // The SSL record header type field (the first byte) is set to 23 if it is an Application Data packet.
            if (rawPayload != null && rawPayload.length >= 5) {
                if (rawPayload[0] == 23) {
                    mTlsApplicationDataPackets.add(packet);
                    // Consider the following packet a data packet if this packet's size == MTU size 1448
                    if (rawPayload.length >= 1448)
                        mApplicationData = true;
                } else if (rawPayload[0] == 20) {
                    // Do nothing for now - CHANGE_CIPHER_SPEC
                } else if (rawPayload[0] == 21) {
                    // Do nothing for now - ALERT
                } else if (rawPayload[0] == 22) {
                    // Do nothing for now - HANDSHAKE
                } else {
                    // If it is TLS with payload, but rawPayload[0] != 23
                    if (mApplicationData == true) {
                        // It is a continuation of the previous packet if the previous packet reaches MTU size 1448 and
                        // it is not either type 20, 21, or 22
                        mTlsApplicationDataPackets.add(packet);
                        if (rawPayload.length < 1448)
                            mApplicationData = false;
                    }
                }
            }
        }
    }

    /**
     * Get a list of packets pertaining to this {@code Conversation}.
     * The returned list is a read-only list.
     * @return the list of packets pertaining to this {@code Conversation}.
     */
    public List<PcapPacket> getPackets() {
        // Return read-only view to prevent external code from manipulating internal state (preserve invariant).
        return Collections.unmodifiableList(mPackets);
    }

    /**
     * Records a TCP SYN packet as pertaining to this conversation (adds it to the the internal list).
     * Attempts to add duplicate SYN packets will be ignored, and the caller is made aware of the attempt to add a
     * duplicate by the return value being {@code false}.
     *
     * @param synPacket A {@link PcapPacket} wrapping a TCP SYN packet.
     * @return {@code true} if the packet was successfully added to this {@code Conversation}, {@code false} otherwise.
     */
    public boolean addSynPacket(PcapPacket synPacket) {
        onAddPrecondition(synPacket);
        final IpV4Packet synPacketIpSection = synPacket.get(IpV4Packet.class);
        final TcpPacket synPacketTcpSection = synPacket.get(TcpPacket.class);
        if (synPacketTcpSection == null || !synPacketTcpSection.getHeader().getSyn()) {
            throw new IllegalArgumentException("Not a SYN packet.");
        }
        // We are only interested in recording one copy of the two SYN packets (one SYN packet in each direction), i.e.,
        // we want to discard retransmitted SYN packets.
        if (mSynPackets.size() >= 2) {
            return false;
        }
        // Check the set of recorded SYN packets to see if we have already recorded a SYN packet going in the same
        // direction as the packet given in the argument.
        boolean matchingPrevSyn = mSynPackets.stream().anyMatch(p -> {
            IpV4Packet pIp = p.get(IpV4Packet.class);
            TcpPacket pTcp = p.get(TcpPacket.class);
            boolean srcAddrMatch = synPacketIpSection.getHeader().getSrcAddr().getHostAddress().
                    equals(pIp.getHeader().getSrcAddr().getHostAddress());
            boolean dstAddrMatch = synPacketIpSection.getHeader().getDstAddr().getHostAddress().
                    equals(pIp.getHeader().getDstAddr().getHostAddress());
            boolean srcPortMatch = synPacketTcpSection.getHeader().getSrcPort().valueAsInt() ==
                    pTcp.getHeader().getSrcPort().valueAsInt();
            boolean dstPortMatch = synPacketTcpSection.getHeader().getDstPort().valueAsInt() ==
                    pTcp.getHeader().getDstPort().valueAsInt();
            return srcAddrMatch && dstAddrMatch && srcPortMatch && dstPortMatch;
        });
        if (matchingPrevSyn) {
            return false;
        }
        // Update direction-dependent set of sequence numbers and record/log packet.
        addSeqNumber(synPacket);
        return mSynPackets.add(synPacket);

        /*
        mSynPackets.stream().anyMatch(p -> {
            IpV4Packet pIp = p.get(IpV4Packet.class);
            TcpPacket pTcp = p.get(TcpPacket.class);
            boolean srcAddrMatch = synPacketIpSection.getHeader().getSrcAddr().getHostAddress().
                    equals(pIp.getHeader().getSrcAddr().getHostAddress());
            boolean dstAddrMatch = synPacketIpSection.getHeader().getDstAddr().getHostAddress().
                    equals(pIp.getHeader().getDstAddr().getHostAddress());
            boolean srcPortMatch = synPacketTcpSection.getHeader().getSrcPort().valueAsInt() ==
                    pTcp.getHeader().getSrcPort().valueAsInt();
            boolean dstPortMatch = synPacketTcpSection.getHeader().getDstPort().value() ==
                    pTcp.getHeader().getDstPort().value();

            boolean fourTupleMatch = srcAddrMatch && dstAddrMatch && srcPortMatch && dstPortMatch;

            boolean seqNoMatch = synPacketTcpSection.getHeader().getSequenceNumber() ==
                    pTcp.getHeader().getSequenceNumber();

            if (fourTupleMatch && !seqNoMatch) {
                // If the four tuple that identifies the conversation matches, but the sequence number is different,
                // it means that this SYN packet is, in fact, an attempt to establish a **new** connection, and hence
                // the given packet is NOT part of this conversation, even though the ip:port combinations are (by
                // chance) selected such that they match this conversation.
                throw new IllegalArgumentException("Attempt to add SYN packet that belongs to a different conversation " +
                        "(which is identified by the same four tuple as this conversation)");
            }
            return fourTupleMatch && seqNoMatch;
        });
        */
    }

    /**
     * Get a list of SYN packets pertaining to this {@code Conversation}.
     * The returned list is a read-only list.
     * @return the list of SYN packets pertaining to this {@code Conversation}.
     */
    public List<PcapPacket> getSynPackets() {
        return Collections.unmodifiableList(mSynPackets);
    }

    /**
     * Adds a TCP FIN packet to the list of TCP FIN packets associated with this conversation.
     * @param finPacket The TCP FIN packet that is to be added to (associated with) this conversation.
     */
    public void addFinPacket(PcapPacket finPacket) {
        // Precondition: verify that packet does indeed pertain to conversation.
        onAddPrecondition(finPacket);
        // TODO: should call addSeqNumber here?
        addSeqNumber(finPacket);
        mFinPackets.add(new FinAckPair(finPacket));
    }

    /**
     * Attempt to ACK any FIN packets held by this conversation.
     * @param ackPacket The ACK for a FIN previously added to this conversation.
     */
    public void attemptAcknowledgementOfFin(PcapPacket ackPacket) {
        // Precondition: verify that the packet pertains to this conversation.
        onAddPrecondition(ackPacket);
        // Mark unack'ed FIN(s) that this ACK matches as ACK'ed (there might be more than one in case of retransmissions..?)
        mFinPackets.replaceAll(finAckPair -> !finAckPair.isAcknowledged() && finAckPair.isCorrespondingAckPacket(ackPacket) ? new FinAckPair(finAckPair.getFinPacket(), ackPacket) : finAckPair);
    }

    /**
     * Retrieves an unmodifiable view of the list of {@link FinAckPair}s associated with this {@code Conversation}.
     * @return an unmodifiable view of the list of {@link FinAckPair}s associated with this {@code Conversation}.
     */
    public List<FinAckPair> getFinAckPairs() {
        return Collections.unmodifiableList(mFinPackets);
    }

    /**
     * Get if this {@code Conversation} is considered to have been gracefully shut down.
     * A {@code Conversation} has been gracefully shut down if it contains a FIN+ACK pair for both directions
     * (client to server, and server to client).
     * @return {@code true} if the connection has been gracefully shut down, false otherwise.
     */
    public boolean isGracefullyShutdown() {
        //  The conversation has been gracefully shut down if we have recorded a FIN from both the client and the server which have both been ack'ed.
        return mFinPackets.stream().anyMatch(finAckPair -> finAckPair.isAcknowledged() && PcapPacketUtils.isSource(finAckPair.getFinPacket(), mClientIp, mClientPort)) &&
                mFinPackets.stream().anyMatch(finAckPair -> finAckPair.isAcknowledged() && PcapPacketUtils.isSource(finAckPair.getFinPacket(), mServerIp, mServerPort));
    }

    /**
     * Add a TCP segment for which the RST flag is set to this {@code Conversation}.
     * @param packet A {@link PcapPacket} wrapping a TCP segment pertaining to this {@code Conversation} for which the
     *               RST flag is set.
     */
    public void addRstPacket(PcapPacket packet) {
        /*
         * TODO:
         * When now also keeping track of RST packets, should we also...?
         * 1) Prevent later packets from being added once a RST segment has been added?
         * 2) Extend 'isGracefullyShutdown()' to also consider RST segments, or add another method, 'isShutdown()' that
         *    both considers FIN/ACK (graceful) as well as RST (abrupt/"ungraceful") shutdown?
         * 3) Should it be impossible to associate more than one RST segment with each Conversation?
         */
        onAddPrecondition(packet);
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket == null || !tcpPacket.getHeader().getRst()) {
            throw new IllegalArgumentException("not a RST packet");
        }
        mRstPackets.add(packet);
    }

    /**
     * Get the TCP segments pertaining to this {@code Conversation} for which it was detected that the RST flag is set.
     * @return the TCP segments pertaining to this {@code Conversation} for which it was detected that the RST flag is
     *         set.
     */
    public List<PcapPacket> getRstPackets() {
        return Collections.unmodifiableList(mRstPackets);
    }

    // =========================================================================================================
    // We simply reuse equals and hashCode methods of String.class to be able to use this class as a key
    // in a Map.

    /**
     * <em>Note:</em> currently, equality is determined based on pairwise equality of the elements of the four tuple
     * ({@link #mClientIp}, {@link #mClientPort}, {@link #mServerIp}, {@link #mServerPort}) for {@code this} and
     * {@code obj}.
     * @param obj The object to test for equality with {@code this}.
     * @return {@code true} if {@code obj} is considered equal to {@code this} based on the definition of equality given above.
     */
    @Override
    public boolean equals(Object obj) {
        return obj instanceof Conversation && this.toString().equals(obj.toString());
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }
    // =========================================================================================================

    @Override
    public String toString() {
        return String.format("%s:%d %s:%d", mClientIp, mClientPort, mServerIp, mServerPort);
    }

    /**
     * Invoke to verify that the precondition holds when a caller attempts to add a packet to this {@code Conversation}.
     * An {@link IllegalArgumentException} is thrown if the precondition is violated.
     * @param packet the packet to be added to this {@code Conversation}
     */
    private void onAddPrecondition(PcapPacket packet) {
        // Apply precondition to preserve class invariant: all packets in mPackets must match the 4 tuple that
        // defines the conversation.
        IpV4Packet ipPacket = Objects.requireNonNull(packet.get(IpV4Packet.class));
        // For now we only support TCP flows.
        TcpPacket tcpPacket = Objects.requireNonNull(packet.get(TcpPacket.class));
        String ipSrc = ipPacket.getHeader().getSrcAddr().getHostAddress();
        String ipDst = ipPacket.getHeader().getDstAddr().getHostAddress();
        int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
        int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
        String clientIp, serverIp;
        int clientPort, serverPort;
        if (ipSrc.equals(mClientIp)) {
            clientIp = ipSrc;
            clientPort = srcPort;
            serverIp = ipDst;
            serverPort = dstPort;
        } else {
            clientIp = ipDst;
            clientPort = dstPort;
            serverIp = ipSrc;
            serverPort = srcPort;
        }
        if (!(clientIp.equals(mClientIp) && clientPort == mClientPort &&
                serverIp.equals(mServerIp) && serverPort == mServerPort)) {
            throw new IllegalArgumentException(
                    String.format("Attempt to add packet that does not pertain to %s",
                            Conversation.class.getSimpleName()));
        }
    }

    /**
     * <p>
     *      Determines if the TCP packet contained in {@code packet} is a retransmission of a previously seen (logged)
     *      packet.
     * </p>
     *
     * <b>
     *     TODO:
     *     the current implementation, which uses a set of previously seen sequence numbers, will consider a segment
     *     with a reused sequence number---occurring as a result of sequence number wrap around for a very long-lived
     *     connection---as a retransmission (and may therefore end up discarding it even though it is in fact NOT a
     *     retransmission). Ideas?
     * </b>
     *
     * @param packet The packet.
     * @return {@code true} if {@code packet} was determined to be a retransmission, {@code false} otherwise.
     */
    public boolean isRetransmission(PcapPacket packet) {
        // Extract sequence number.
        int seqNo = packet.get(TcpPacket.class).getHeader().getSequenceNumber();
        switch (getDirection(packet)) {
            case CLIENT_TO_SERVER:
                return mSeqNumbersClient.contains(seqNo);
            case SERVER_TO_CLIENT:
                return mSeqNumbersSrv.contains(seqNo);
            default:
                throw new AssertionError(String.format("Unexpected value of enum '%s'",
                        Direction.class.getSimpleName()));
        }
    }

    /**
     * <p>
     *     Is this {@code Conversation} a TLS session?
     * </p>
     *
     * <em>Note: the current implementation simply examines the port number(s) for 443; it does <b>not</b> verify if the
     * application data is indeed encrypted.</em>
     *
     * @return {@code true} if this {@code Conversation} is interpreted as a TLS session, {@code false} otherwise.
     */
    public boolean isTls() {
        /*
         * TODO:
         * - may want to change this to be "return mServerPort == 443 || mClientPort == 443;" in order to also detect
         *   TLS in those cases where it is not possible to correctly label who is the client and who is the server,
         *   i.e., when the trace does not contain the SYN/SYNACK exchange.
         * - current implementation relies on the server using the conventional TLS port number; may instead want to
         *   inspect the first 4 bytes of each potential TLS packet to see if they match the SSL record header.
         *
         * 08/31/18: Added unconvetional TLS ports used by WeMo plugs and LiFX bulb.
         * 09/20/18: Moved hardcoded ports to other class to allow other classes to query the set of TLS ports.
         */
        return TcpConversationUtils.isTlsPort(mServerPort);
    }

    /**
     * If this {@code Conversation} is backing a TLS session (i.e., if the value of {@link #isTls()} is {@code true}),
     * get the packets labeled as TLS Application Data packets. This is a subset of the full set of payload-carrying
     * packets (as returned by {@link #getPackets()}). An exception is thrown if this method is invoked on a
     * {@code Conversation} for which {@link #isTls()} returns {@code false}.
     *
     * @return A list containing exactly those packets that could be identified as TLS Application Data packets (through
     *         inspecting of the SSL record header). The list may be empty, if no TLS application data packets have been
     *         recorded for this {@code Conversation}.
     */
    public List<PcapPacket> getTlsApplicationDataPackets() {
        if (!isTls()) {
            throw new NoSuchElementException("cannot get TLS Application Data packets for non-TLS TCP conversation");
        }
        return Collections.unmodifiableList(mTlsApplicationDataPackets);
    }

    /**
     * Extracts the TCP sequence number from {@code packet} and adds it to the proper set of sequence numbers by
     * analyzing the direction of the packet.
     * @param packet A TCP packet (wrapped in a {@code PcapPacket}) that was added to this conversation and whose
     *               sequence number is to be recorded as seen.
     */
    private void addSeqNumber(PcapPacket packet) {
        // Note: below check is redundant if client code is correct as the call to check the precondition should already
        // have been made by the addXPacket method that invokes this method. As such, the call below may be removed in
        // favor of speed, but the improvement will be minor, hence the added safety may be worth it.
        onAddPrecondition(packet);
        // Extract sequence number.
        int seqNo = packet.get(TcpPacket.class).getHeader().getSequenceNumber();
        // Determine direction of packet and add packet's sequence number to corresponding set of sequence numbers.
        switch (getDirection(packet)) {
            case CLIENT_TO_SERVER:
                // Client to server packet.
                mSeqNumbersClient.add(seqNo);
                break;
            case SERVER_TO_CLIENT:
                // Server to client packet.
                mSeqNumbersSrv.add(seqNo);
                break;
            default:
                throw new AssertionError(String.format("Unexpected value of enum '%s'",
                        Direction.class.getSimpleName()));
        }
    }

    /**
     * Determine the direction of {@code packet}. An {@link IllegalArgumentException} is thrown if {@code packet} does
     * not pertain to this conversation.
     *
     * @param packet The packet whose direction is to be determined.
     * @return A {@link Direction} indicating the direction of the packet.
     */
    public Direction getDirection(PcapPacket packet) {
        IpV4Packet ipPacket = packet.get(IpV4Packet.class);
        String ipSrc = ipPacket.getHeader().getSrcAddr().getHostAddress();
        String ipDst = ipPacket.getHeader().getDstAddr().getHostAddress();
        // Determine direction of packet.
        if (ipSrc.equals(mClientIp) && ipDst.equals(mServerIp)) {
            // Client to server packet.
            return Direction.CLIENT_TO_SERVER;
        } else if (ipSrc.equals(mServerIp) && ipDst.equals(mClientIp)) {
            // Server to client packet.
            return Direction.SERVER_TO_CLIENT;
        } else {
            throw new IllegalArgumentException("getDirection: packet not related to " + getClass().getSimpleName());
        }
    }

    /**
     * Utility enum for expressing the direction of a packet pertaining to this {@code Conversation}.
     */
    public enum Direction {

        CLIENT_TO_SERVER {
            @Override
            public String toCompactString() {
                return "*";
            }
        },
        SERVER_TO_CLIENT {
            @Override
            public String toCompactString() {
                return "";
            }
        };

        /**
         * Get a compact string representation of this {@code Direction}.
         * @return a compact string representation of this {@code Direction}.
         */
        abstract public String toCompactString();

    }

}
