package edu.uci.iotproject;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;

import java.io.EOFException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.TimeoutException;

/**
 * TODO add class documentation.
 * TODO: At this point, this class is still in transition to having multiple hostnames and lists of packets
 *
 * @author Janus Varmarken
 */
public class FlowPattern {

    /**
     * Class properties
     */
    private final String mPatternId;
    private final String hostname;  // The hostname that this {@code FlowPattern} is associated with.

    /**
     * The order of packet lengths that defines this {@link FlowPattern}
     * TODO: this is a simplified representation, we should also include information about direction of each packet.
     */
    private final List<Integer> flowPacketOrder;
    private final Map<String, List<Integer>> mHostnameToPacketLengthsMap;
    private final List<String> mHostnameList;
    private final PcapHandle mPcap;

    
    /**
     * Class constants
     */
     

    /**
     * Constructor #1
     */
    public FlowPattern(String mPatternId, String hostname, PcapHandle mPcap) {
        this.mPatternId = mPatternId;
        this.hostname = hostname;
        this.mHostnameList = null;
        this.mPcap = mPcap;
        this.mHostnameToPacketLengthsMap = null;
        this.flowPacketOrder = new ArrayList<Integer>();
        processPcap();
    }


    /**
     * Process the PcapHandle to strip off unnecessary packets and just get the integer array of packet lengths
     */
    private void processPcap() {

        PcapPacket packet;
        try {
            while ((packet = mPcap.getNextPacketEx()) != null) {
                // For now, we only work support pattern search in TCP over IPv4.
                IpV4Packet ipPacket = packet.get(IpV4Packet.class);
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                if (ipPacket == null || tcpPacket == null)
                    continue;
                if (tcpPacket.getPayload() == null) // We skip non-payload control packets as these are less predictable
                    continue; 
                int packetLength = tcpPacket.getPayload().length();
                flowPacketOrder.add(packetLength);
            }
        } catch (EOFException eofe) {
            System.out.println("[ FlowPattern ] Finished processing a training PCAP stream!");
            System.out.println("[ FlowPattern ] Pattern for " + mPatternId + ": " + Arrays.toString(flowPacketOrder.toArray()));
        } catch (PcapNativeException  |
                 TimeoutException     |
                 NotOpenException ex) {
            ex.printStackTrace();
        }
    }


    /**
     * Process the PcapHandle to strip off unnecessary packets.
     * We then map list of hostnames to their respective arrays of packet lengths
     */
    private void processPcapToMap() {

        PcapPacket packet;
        try {
            int hostIndex = -1;
            Set<String> addressSet = new HashSet<>();
            while ((packet = mPcap.getNextPacketEx()) != null) {
                // For now, we only work support pattern search in TCP over IPv4.
                IpV4Packet ipPacket = packet.get(IpV4Packet.class);
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                if (ipPacket == null || tcpPacket == null) {
                    continue;
                }
                if (tcpPacket.getPayload() == null) {
                // We skip non-payload control packets as these are less predictable
                    continue;
                }
                // We assume that if it is not a local address then it is a cloud server address
                InetAddress srcAddress = ipPacket.getHeader().getSrcAddr();
                InetAddress dstAddress = ipPacket.getHeader().getDstAddr();
                boolean fromServer = !srcAddress.isSiteLocalAddress();
                boolean fromClient = !dstAddress.isSiteLocalAddress();
                if (!fromServer && !fromClient) {
                    // Packet not related to pattern, skip it
                    continue;
                } else {
                    // We relate and assume that this address is from our cloud server
                    String cloudAddress = null;
                    if (fromClient) {
                        cloudAddress = dstAddress.getHostAddress();
                    } else { // fromServer
                        cloudAddress = srcAddress.getHostAddress();
                    }
                    //System.out.println("\nCloud address: " + cloudAddress);
                    if (!addressSet.contains(cloudAddress)) {
                        addressSet.add(cloudAddress);
                        hostIndex++;
                    }

                    String hostname = mHostnameList.get(hostIndex);
                    List<Integer> packetLengthsList = mHostnameToPacketLengthsMap.containsKey(hostname) ? 
                        mHostnameToPacketLengthsMap.get(hostname) : new ArrayList<>();
                    int packetLength = tcpPacket.getPayload().length();
                    packetLengthsList.add(packetLength);
                    mHostnameToPacketLengthsMap.put(hostname, packetLengthsList);
                }
            }
        } catch (EOFException eofe) {
            System.out.println("[ FlowPattern ] Finished processing a training PCAP stream!");
            System.out.println("[ FlowPattern ] Pattern for " + mPatternId + ": " + Arrays.toString(mHostnameToPacketLengthsMap.entrySet().toArray()));
        } catch (PcapNativeException  |
                 TimeoutException     |
                 NotOpenException ex) {
            ex.printStackTrace();
        }
    }

    
    /**
     * Constructor #2
     */
    public FlowPattern(String mPatternId, List<String> mHostnameList, PcapHandle mPcap) {
        this.mPatternId = mPatternId;
        this.hostname = null;
        this.mHostnameList = mHostnameList;
        this.mPcap = mPcap;
        this.flowPacketOrder = null;
        this.mHostnameToPacketLengthsMap = new HashMap<>();
        processPcapToMap();
    }


    public String getPatternId() {
        return mPatternId;
    }


    public String getHostname() {
        return hostname;
    }


    /**
     * Get the sequence of packet lengths that defines this {@code FlowPattern}.
     * @return the sequence of packet lengths that defines this {@code FlowPattern}.
     */
    public List<Integer> getPacketOrder() {
        return flowPacketOrder;
    }


    /**
     * Get the sequence of packet lengths based on input hostname.
     * @return the sequence of packet lengths that defines this {@code FlowPattern}.
     */
    public List<Integer> getPacketOrder(String hostname) {
        return mHostnameToPacketLengthsMap.get(hostname);
    }


    /**
     * Get the list of associated hostnames.
     * @return the associated hostnames that define this {@code FlowPattern}.
     */
    public List<String> getHostnameList() {
        return mHostnameList;
    }

    
    /**
     * Get the length of the List of {@code FlowPattern}.
     * @return the length of the List of {@code FlowPattern}.
     */
    public int getLength() {
        return flowPacketOrder.size();
    }  


    /**
     * Get the length of the List of {@code FlowPattern}.
     * @return the length of the List of {@code FlowPattern}.
     */
    public int getLength(String hostname) {
        return mHostnameToPacketLengthsMap.get(hostname).size();
    } 
}
