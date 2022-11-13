package edu.uci.iotproject.trafficreassembly.layer3;

import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.packet.*;

import java.util.*;

/**
 * Reassembles TCP conversations (streams).
 * <b>Note: current version only supports TCP over IPv4.</b>
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class TcpReassembler implements PacketListener {

    /**
     * Holds <em>open</em> {@link Conversation}s, i.e., {@code Conversation}s that have <em>not</em> been detected as
     * (gracefully) terminated based on the set of packets observed thus far.
     * A {@link Conversation} is moved to {@link #mTerminatedConversations} if it can be determined that it is has
     * terminated. Termination can be detected by a) observing two {@link FinAckPair}s, one in each direction, (graceful
     * termination, see {@link Conversation#isGracefullyShutdown()}) or b) by observing a SYN packet that matches the
     * four tuple of an existing {@code Conversation}, but which holds a <em>different</em> sequence number than the
     * same-direction SYN packet recorded for the {@code Conversation}.
     * <p>
     * Note that due to limitations of the {@link Set} interface (specifically, there is no {@code get(T t)} method),
     * we have to resort to a {@link Map} (in which keys map to themselves) to "mimic" a set with {@code get(T t)}
     * functionality.
     *
     * @see <a href="https://stackoverflow.com/questions/7283338/getting-an-element-from-a-set">this question on StackOverflow.com</a>
     */
    private final Map<Conversation, Conversation> mOpenConversations = new HashMap<>();

    /**
     * Holds <em>terminated</em> {@link Conversation}s.
     */
    private final List<Conversation> mTerminatedConversations = new ArrayList<>();
		
		/**
     * IP of the router's WAN port (if analyzed traffic is captured at the ISP's point of view).
     */
    private final String mRouterWanIp;
		private static final String ROUTER_WAN_IP = "128.195.205.105";
		
    public TcpReassembler() {
        mRouterWanIp = ROUTER_WAN_IP;
    }
		
    public TcpReassembler(String routerWanIp) {
        mRouterWanIp = routerWanIp;
    }

    @Override
    public void gotPacket(PcapPacket pcapPacket) {
        IpV4Packet ipPacket = pcapPacket.get(IpV4Packet.class);
        TcpPacket tcpPacket = pcapPacket.get(TcpPacket.class);

        if (ipPacket == null || tcpPacket == null) {
            return;
        }
        // ... TODO?
        processPacket(pcapPacket);
//        Class clazz = pcapPacket.getClass();
//        RadiotapPacket radiotapPacket = pcapPacket.get(RadiotapPacket.class);
//        Dot11ManagementPacket dot11ManagementPacket = pcapPacket.get(Dot11ManagementPacket.class);
//        if (dot11ManagementPacket != null) {
//            return;
//        }
//        if (radiotapPacket != null) {
//            processRadiotapPacket(pcapPacket);
//        }
    }

    /**
     * Get the reassembled TCP connections. Note that if this is called while packets are still being processed (by
     * calls to {@link #gotPacket(PcapPacket)}), the behavior is undefined and the returned list may be inconsistent.
     * @return The reassembled TCP connections.
     */
    public List<Conversation> getTcpConversations() {
        ArrayList<Conversation> combined = new ArrayList<>();
        combined.addAll(mTerminatedConversations);
        combined.addAll(mOpenConversations.values());
        return combined;
    }

    private void processRadiotapPacket(PcapPacket pcapPacket) {
        RadiotapPacket radiotapPacket = pcapPacket.get(RadiotapPacket.class);

        RadiotapPacket.RadiotapHeader header = radiotapPacket.getHeader();
        short length = header.getLength();
        ArrayList<RadiotapPacket.RadiotapData> radiotapData = header.getDataFields();
        // TODO: We can handle this 802.11 QoS data by creating our own class
        // TODO: We only need to handle the first few bytes for source, destination, receiver, and transmitter
        // TODO: addresses
        Packet dataPacket = radiotapPacket.getPayload();
        int dataLength = dataPacket.length();
    }

    private void processPacket(PcapPacket pcapPacket) {
        TcpPacket tcpPacket = pcapPacket.get(TcpPacket.class);
        // Handle client connection initiation attempts.
        if (tcpPacket.getHeader().getSyn() && !tcpPacket.getHeader().getAck()) {
            // A segment with the SYN flag set, but no ACK flag indicates that a client is attempting to initiate a new
            // connection.
            processNewConnectionRequest(pcapPacket);
            return;
        }
        // Handle server connection initiation acknowledgement
        if (tcpPacket.getHeader().getSyn() && tcpPacket.getHeader().getAck()) {
            // A segment with both the SYN and ACK flags set indicates that the server has accepted the client's request
            // to initiate a new connection.
            processNewConnectionAck(pcapPacket);
            return;
        }
        // Handle resets
        if (tcpPacket.getHeader().getRst()) {
            processRstPacket(pcapPacket);
            return;
        }
        // Handle FINs
        if (tcpPacket.getHeader().getFin()) {
            // Handle FIN packet.
            processFinPacket(pcapPacket);
        }
        // Handle ACKs (currently only ACKs of FINS)
        if (tcpPacket.getHeader().getAck()) {
            processAck(pcapPacket);
        }
        // Handle packets that carry payload (application data).
        if (tcpPacket.getPayload() != null) {
            processPayloadPacket(pcapPacket);
        }
    }

    private void processNewConnectionRequest(PcapPacket clientSynPacket) {
        // A SYN w/o ACK always originates from the client.
        Conversation conv = Conversation.fromPcapPacket(clientSynPacket, true);
        conv.addSynPacket(clientSynPacket);
        // Is there an ongoing conversation for the same four tuple (clientIp, clientPort, serverIp, serverPort) as
        // found in the new SYN packet?
        Conversation ongoingConv = mOpenConversations.get(conv);
        if (ongoingConv != null) {
            if (ongoingConv.isRetransmission(clientSynPacket)) {
                // SYN retransmission detected, do nothing.
                return;
                // TODO: the way retransmission detection is implemented may cause a bug for connections where we have
                // not recorded the initial SYN, but only the SYN ACK, as retransmission is determined by comparing the
                // sequence numbers of initial SYNs -- and if no initial SYN is present for the Conversation, the new
                // SYN will be interpreted as a retransmission. Possible fix: let isRentransmission ALWAYS return false
                // when presented with a SYN packet when the Conversation already holds a SYN ACK packet?
            } else {
                // New SYN has different sequence number than SYN recorded for ongoingConv, so this must be an attempt
                // to establish a new conversation with the same four tuple as ongoingConv.
                // Mark existing connection as terminated.
                // TODO: is this 100% theoretically correct, e.g., if many connection attempts are made back to back? And RST packets?
                mTerminatedConversations.add(ongoingConv);
                mOpenConversations.remove(ongoingConv);
            }
        }
        // Finally, update the map of open connections with the new connection.
        mOpenConversations.put(conv, conv);
    }


    /*
     * TODO a problem across the board for all processXPacket methods below:
     * if we start the capture in the middle of a TCP connection, we will not have an entry for the conversation in the
     * map as we have not seen the initial SYN packet.
     * Two ways we can address this:
     * a) Perform null-checks and ignore packets for which we have not seen SYN
     *    + easy to get correct
     *    - we discard data (issue for long-lived connections!)
     * b) Add a corresponding conversation entry whenever we encounter a packet that does not map to a conversation
     *    + we consider all data
     *    - not immediately clear if this will introduce bugs (incorrectly mapping packets to wrong conversations?)
     *
     *  [[[ I went with option b) for now; see getOngoingConversationOrCreateNew(PcapPacket pcapPacket). ]]]
     */

    private void processNewConnectionAck(PcapPacket srvSynPacket) {
        // Find the corresponding ongoing connection, if any (if we start the capture just *after* the initial SYN, no
        // ongoing conversation entry will exist, so it must be created in that case).
//        Conversation conv = mOpenConversations.get(Conversation.fromPcapPacket(srvSynPacket, false));
        Conversation conv = getOngoingConversationOrCreateNew(srvSynPacket);
        // Note: exploits &&'s short-circuit operation: only attempts to add non-retransmissions.
        if (!conv.isRetransmission(srvSynPacket) && !conv.addSynPacket(srvSynPacket)) {
            // For safety/debugging: if NOT a retransmission and add fails,
            // something has gone terribly wrong/invariant is broken.
//            throw new AssertionError("Attempt to add SYN ACK packet that was NOT a retransmission failed." +
//                    Conversation.class.getSimpleName() + " invariant broken.");
        }
    }

    private void processRstPacket(PcapPacket rstPacket) {
        Conversation conv = getOngoingConversationOrCreateNew(rstPacket);
        // Add RST packet to conversation.
        conv.addRstPacket(rstPacket);
        // Move conversation to set of terminated conversations.
        mTerminatedConversations.add(conv);
        mOpenConversations.remove(conv, conv);
    }

    private void processFinPacket(PcapPacket finPacket) {
//        getOngoingConversationForPacket(finPacket).addFinPacket(finPacket);
        getOngoingConversationOrCreateNew(finPacket).addFinPacket(finPacket);
    }

    private void processAck(PcapPacket ackPacket) {
//        getOngoingConversationForPacket(ackPacket).attemptAcknowledgementOfFin(ackPacket);
        // Note that unlike the style for SYN, FIN, and payload packets, for "ACK only" packets, we want to avoid
        // creating a new conversation.
        Conversation conv = getOngoingConversationForPacket(ackPacket);
        if (conv != null) {
            // The ACK may be an ACK of a FIN, so attempt to mark the FIN as ack'ed.
            conv.attemptAcknowledgementOfFin(ackPacket);
            if (conv.isGracefullyShutdown()) {
                // Move conversation to set of terminated conversations.
                mTerminatedConversations.add(conv);
                mOpenConversations.remove(conv);
            }
        }
        // Note: add (additional) processing of ACKs (that are not ACKs of FINs) as necessary here...
    }

    private void processPayloadPacket(PcapPacket pcapPacket) {
//        getOngoingConversationForPacket(pcapPacket).addPacket(pcapPacket, true);
        getOngoingConversationOrCreateNew(pcapPacket).addPacket(pcapPacket, true);
    }

    /**
     * Locates an ongoing conversation (if any) that {@code pcapPacket} pertains to.
     * @param pcapPacket The packet that is to be mapped to an ongoing {@code Conversation}.
     * @return The {@code Conversation} matching {@code pcapPacket} or {@code null} if there is no match.
     */
    private Conversation getOngoingConversationForPacket(PcapPacket pcapPacket) {
        // We cannot know if this is a client-to-server or server-to-client packet without trying both options...
        Conversation conv = mOpenConversations.get(Conversation.fromPcapPacket(pcapPacket, true));
        if (conv == null) {
            conv = mOpenConversations.get(Conversation.fromPcapPacket(pcapPacket, false));
        }
        return conv;
    }

    /**
     * Like {@link #getOngoingConversationForPacket(PcapPacket)}, but creates and inserts a new {@code Conversation}
     * into {@link #mOpenConversations} if no open conversation is found (i.e., in the case that
     * {@link #getOngoingConversationForPacket(PcapPacket)} returns {@code null}).
     *
     * @param pcapPacket The packet that is to be mapped to an ongoing {@code Conversation}.
     * @return The existing, ongoing {@code Conversation} matching {@code pcapPacket} or the newly created one in case
     *         no match was found.
     */
    private Conversation getOngoingConversationOrCreateNew(PcapPacket pcapPacket) {
        Conversation conv = getOngoingConversationForPacket(pcapPacket);
        if (conv == null) {
            TcpPacket tcpPacket = pcapPacket.get(TcpPacket.class);
            if (tcpPacket.getHeader().getSyn() && tcpPacket.getHeader().getAck()) {
                // A SYN ACK packet always originates from the server (it is a reply to the initial SYN packet from the client)
                conv = Conversation.fromPcapPacket(pcapPacket, false);
            } else {
                // TODO: can we do anything else but arbitrarily select who is designated as the server in this case?
                // We can check if the IP prefix matches a local IP when handling traffic observed inside the local
                // network, but that obviously won't be a useful strategy for an observer at the WAN port.
                String srcIp = pcapPacket.get(IpV4Packet.class).getHeader().getSrcAddr().getHostAddress();
                // TODO: REPLACE THE ROUTER'S IP WITH A PARAMETER!!!
                boolean clientIsSrc = srcIp.startsWith("10.") || srcIp.startsWith("192.168.") || srcIp.equals(mRouterWanIp);
                conv = Conversation.fromPcapPacket(pcapPacket, clientIsSrc);
            }
            mOpenConversations.put(conv, conv);
        }
        return conv;
    }
}
