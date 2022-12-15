package edu.uci.iotproject.util;

import edu.uci.iotproject.io.PrintWriterUtils;
import edu.uci.iotproject.trafficreassembly.layer3.Conversation;
import edu.uci.iotproject.analysis.PcapPacketPair;
import edu.uci.iotproject.analysis.TcpConversationUtils;
import edu.uci.iotproject.analysis.TriggerTrafficExtractor;
import org.apache.commons.math3.stat.clustering.Cluster;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.util.MacAddress;

import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.*;

/**
 * Utility methods for inspecting {@link PcapPacket} properties.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public final class PcapPacketUtils {

    /**
     * This is the threshold value for a signature's number of members
     * If after a merging the number of members of a signature falls below this threshold, then we can boldly
     * get rid of that signature.
     */
    private static final int SIGNATURE_MERGE_THRESHOLD = 5;

    /**
     * This is an overlap counter (we consider overlaps between signatures if it happens more than once)
     */
    private static int mOverlapCounter = 0;


    /**
     * Gets the source address of the Ethernet part of {@code packet}.
     * @param packet The packet for which the Ethernet source address is to be extracted.
     * @return The source address of the Ethernet part of {@code packet}.
     */
    public static MacAddress getEthSrcAddr(PcapPacket packet) {
        return getEthernetPacketOrThrow(packet).getHeader().getSrcAddr();
    }

    /**
     * Gets the destination address of the Ethernet part of {@code packet}.
     * @param packet The packet for which the Ethernet destination address is to be extracted.
     * @return The destination address of the Ethernet part of {@code packet}.
     */
    public static MacAddress getEthDstAddr(PcapPacket packet) {
        return getEthernetPacketOrThrow(packet).getHeader().getDstAddr();
    }

    /**
     * Determines if a given {@link PcapPacket} wraps a {@link TcpPacket}.
     * @param packet The {@link PcapPacket} to inspect.
     * @return {@code true} if {@code packet} wraps a {@link TcpPacket}, {@code false} otherwise.
     */
    public static boolean isTcp(PcapPacket packet) {
        return packet.get(TcpPacket.class) != null;
    }

    /**
     * Gets the source IP (in decimal format) of an IPv4 packet.
     * @param packet The packet for which the IPv4 source address is to be extracted.
     * @return The decimal representation of the source IP of {@code packet} <em>iff</em> {@code packet} wraps an
     *         {@link IpV4Packet}.
     * @throws NullPointerException if {@code packet} does not encapsulate an {@link IpV4Packet}.
     */
    public static String getSourceIp(PcapPacket packet) {
        return getIpV4PacketOrThrow(packet).getHeader().getSrcAddr().getHostAddress();
    }

    /**
     * Gets the destination IP (in decimal format) of an IPv4 packet.
     * @param packet The packet for which the IPv4 source address is to be extracted.
     * @return The decimal representation of the destination IP of {@code packet} <em>iff</em> {@code packet} wraps an
     *         {@link IpV4Packet}.
     * @throws NullPointerException if {@code packet} does not encapsulate an {@link IpV4Packet}.
     */
    public static String getDestinationIp(PcapPacket packet) {
        return getIpV4PacketOrThrow(packet).getHeader().getDstAddr().getHostAddress();
    }

    /**
     * Gets the source port of a TCP packet.
     * @param packet The packet for which the source port is to be extracted.
     * @return The source port of the {@link TcpPacket} encapsulated by {@code packet}.
     * @throws IllegalArgumentException if {@code packet} does not encapsulate a {@link TcpPacket}.
     */
    public static int getSourcePort(PcapPacket packet) {
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket == null) {
            throw new IllegalArgumentException("not a TCP packet");
        }
        return tcpPacket.getHeader().getSrcPort().valueAsInt();
    }

    /**
     * Gets the destination port of a TCP packet.
     * @param packet The packet for which the destination port is to be extracted.
     * @return The destination port of the {@link TcpPacket} encapsulated by {@code packet}.
     * @throws IllegalArgumentException if {@code packet} does not encapsulate a {@link TcpPacket}.
     */
    public static int getDestinationPort(PcapPacket packet) {
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket == null) {
            throw new IllegalArgumentException("not a TCP packet");
        }
        return tcpPacket.getHeader().getDstPort().valueAsInt();
    }

    /**
     * Helper method to determine if the given combination of IP and port matches the source of the given packet.
     * @param packet The packet to check.
     * @param ip The IP to look for in the ip.src field of {@code packet}.
     * @param port The port to look for in the tcp.port field of {@code packet}.
     * @return {@code true} if the given ip+port match the corresponding fields in {@code packet}.
     */
    public static boolean isSource(PcapPacket packet,         String ip, int port) {
        IpV4Packet ipPacket = Objects.requireNonNull(packet.get(IpV4Packet.class));
        // For now we only support TCP flows.
        TcpPacket tcpPacket = Objects.requireNonNull(packet.get(TcpPacket.class));
        String ipSrc = ipPacket.getHeader().getSrcAddr().getHostAddress();
        int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
        return ipSrc.equals(ip) && srcPort == port;
    }

    /**
     * Helper method to determine if the given combination of IP and port matches the destination of the given packet.
     * @param packet The packet to check.
     * @param ip The IP to look for in the ip.dst field of {@code packet}.
     * @param port The port to look for in the tcp.dstport field of {@code packet}.
     * @return {@code true} if the given ip+port match the corresponding fields in {@code packet}.
     */
    public static boolean isDestination(PcapPacket packet, String ip, int port) {
        IpV4Packet ipPacket = Objects.requireNonNull(packet.get(IpV4Packet.class));
        // For now we only support TCP flows.
        TcpPacket tcpPacket = Objects.requireNonNull(packet.get(TcpPacket.class));
        String ipDst = ipPacket.getHeader().getDstAddr().getHostAddress();
        int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
        return ipDst.equals(ip) && dstPort == port;
    }

    /**
     * Checks if the source IP address of the {@link IpV4Packet} contained in {@code packet} is a local address, i.e.,
     * if it pertains to subnet 10.0.0.0/8, 172.16.0.0/16, or 192.168.0.0/16.
     * @param packet The packet for which the source IP address is to be examined.
     * @return {@code true} if {@code packet} wraps a {@link IpV4Packet} for which the source IP address is a local IP
     *         address, {@code false} otherwise.
     * @throws NullPointerException if {@code packet} does not encapsulate an {@link IpV4Packet}.
     */
    public static boolean isSrcIpLocal(PcapPacket packet) {
        return getIpV4PacketOrThrow(packet).getHeader().getSrcAddr().isSiteLocalAddress();
    }

    /**
     * Checks if the destination IP address of the {@link IpV4Packet} contained in {@code packet} is a local address,
     * i.e., if it pertains to subnet 10.0.0.0/8, 172.16.0.0/16, or 192.168.0.0/16.
     * @param packet The packet for which the destination IP address is to be examined.
     * @return {@code true} if {@code packet} wraps a {@link IpV4Packet} for which the destination IP address is a local
     *         IP address, {@code false} otherwise.
     * @throws NullPointerException if {@code packet} does not encapsulate an {@link IpV4Packet}.
     */
    public static boolean isDstIpLocal(PcapPacket packet) {
        return getIpV4PacketOrThrow(packet).getHeader().getDstAddr().isSiteLocalAddress();
    }

    /**
     * Checks if {@code packet} wraps a TCP packet that has the SYN flag set.
     * @param packet A {@link PcapPacket} that is suspected to contain a {@link TcpPacket} for which the SYN flag is set.
     * @return {@code true} <em>iff</em> {@code packet} contains a {@code TcpPacket} for which the SYN flag is set,
     *         {@code false} otherwise.
     */
    public static boolean isSyn(PcapPacket packet) {
        TcpPacket tcp = packet.get(TcpPacket.class);
        return tcp != null && tcp.getHeader().getSyn();
    }

    /**
     * Checks if {@code packet} wraps a TCP packet th        at has the ACK flag set.
     * @param packet A {@link PcapPacket} that is suspected to contain a {@link TcpPacket} for which the ACK flag is set.
     * @return {@code true} <em>iff</em> {@code packet} contains a {@code TcpPacket} for which the ACK flag is set,
     *         {@code false} otherwise.
     */
    public static boolean isAck(PcapPacket packet) {
        TcpPacket tcp = packet.get(TcpPacket.class);
        return tcp != null && tcp.getHeader().getAck();
    }

    /**
     * Transform a {@code Cluster} of {@code PcapPacketPair} objects into a {@code List} of {@code List} of
     * {@code PcapPacket} objects.
     * @param cluster A {@link Cluster} of {@link PcapPacketPair} objects that needs to be transformed.
     * @return A {@link List} of {@link List} of {@link PcapPacket} objects as the result of the transformation.
     */
    public static List<List<PcapPacket>> clusterToListOfPcapPackets(Cluster<PcapPacketPair> cluster) {
        List<List<PcapPacket>> ppListOfList = new ArrayList<>();
        for (PcapPacketPair ppp: cluster.getPoints()) {
            // Create a list of PcapPacket objects (list of two members).
            List<PcapPacket> ppList = new ArrayList<>();
            ppList.add(ppp.getFirst());
            if(ppp.getSecond().isPresent())
                ppList.add(ppp.getSecond().get());
            else
                ppList.add(null);
            // Create a list of list of PcapPacket objects.
            ppListOfList.add(ppList);
        }
        // Sort the list of lists based on the first packet's timestamp!
        Collections.sort(ppListOfList, (p1, p2) -> p1.get(0).getTimestamp().compareTo(p2.get(0).getTimestamp()));
        return ppListOfList;
    }

    /**
     * Concatenate sequences in {@code List} of {@code List} of {@code List} of {@code PcapPacket} objects.
     * We cross-check these with {@code List} of {@code Conversation} objects to see
     * if two {@code List} of {@code PcapPacket} objects actually belong to the same {@code Conversation}.
     * @param signatures A {@link List} of {@link List} of {@link List} of
     *          {@link PcapPacket} objects that needs to be checked and concatenated.
     * @param conversations A {@link List} of {@link Conversation} objects as reference for concatenation.
     * @return A {@link List} of {@link List} of {@link List} of
     *          {@link PcapPacket} objects as the result of the concatenation.
     */
    public static List<List<List<PcapPacket>>>
            concatSequences(List<List<List<PcapPacket>>> signatures, List<Conversation> conversations) {

        // TODO: THIS IS NOT A DEEP COPY; IT BASICALLY CREATES A REFERENCE TO THE SAME LIST OBJECT
        // List<List<List<PcapPacket>>> copySignatures = new ArrayList<>(signatures);
        // Make a deep copy first.
        List<List<List<PcapPacket>>> copySignatures = new ArrayList<>();
        listDeepCopy(copySignatures, signatures);
        // Traverse and look into the pairs.
        //for (int first = 0; first < signatures.size(); first++) {
        int first = 0;
        int signaturesSize = signatures.size();
        while(first < signaturesSize) {
//            System.out.println("First: " + first + " Signatures: " + signatures.get(0).size());
            List<List<PcapPacket>> firstList = signatures.get(first);
            for (int second = first+1; second < signatures.size(); second++) {
                int maxSignatureEl = 0;
                List<List<PcapPacket>> secondList = signatures.get(second);
                int initialSecondListMembers = secondList.size();
                // Iterate over the sequences in the first list.
                for (List<PcapPacket> signature : firstList) {
                    signature.removeIf(el -> el == null); // Clean up null elements.
                    // Return the Conversation that the sequence is part of.
                    Conversation conv = TcpConversationUtils.returnConversation(signature, conversations);
                    // Find the element of the second list that is a match for that Conversation.
                    for (List<PcapPacket> ppList : secondList) {
                        ppList.removeIf(el -> el == null); // Clean up null elements.
                        // Check if they are part of a Conversation and are adjacent to the first sequence.
                        // If yes then merge into the first list.
                        TcpConversationUtils.SignaturePosition position =
                                TcpConversationUtils.isPartOfConversationAndAdjacent(signature, ppList, conv);
                        if (position == TcpConversationUtils.SignaturePosition.LEFT_ADJACENT) {
                            // Merge to the left side of the first sequence.
                            ppList.addAll(signature);
                            // Remove and then add again to keep the same reference
                            signature.removeAll(signature);
                            signature.addAll(ppList);
                            maxSignatureEl = signature.size() > maxSignatureEl ? signature.size() : maxSignatureEl;
                            secondList.remove(ppList); // Remove as we merge.
                            break;
                        } else if (position == TcpConversationUtils.SignaturePosition.RIGHT_ADJACENT) {
                            // Merge to the right side of the first sequence.
                            signature.addAll(ppList);
                            maxSignatureEl = signature.size() > maxSignatureEl ? signature.size() : maxSignatureEl;
                            secondList.remove(ppList); // Remove as we merge.
                            break;
                        } // TcpConversationUtils.SignaturePosition.NOT_ADJACENT.
                    }
                }
//                System.out.println("First list size: " + firstList.get(35).size());
                // Call it a successful merging if there are only less than 5 elements from the second list that
                // cannot be merged.
                if (secondList.size() < SIGNATURE_MERGE_THRESHOLD) {
                    // Prune the unsuccessfully merged sequences (i.e., these will have size() < maxSignatureEl).
                    final int maxNumOfEl = maxSignatureEl;
                    // TODO: DOUBLE CHECK IF WE REALLY NEED TO PRUNE FAILED BINDINGS
                    // TODO: SOMETIMES THE SEQUENCES ARE JUST INCOMPLETE
                    // TODO: AND BOTH THE COMPLETE AND INCOMPLETE SEQUENCES ARE VALID SIGNATURES!
                    firstList.removeIf(el -> el.size() < maxNumOfEl);
                    // Remove the merged set of sequences when successful.
                    signatures.remove(secondList);
                } else if (secondList.size() < initialSecondListMembers) {
                    // If only some of the sequences from the second list are merged, this means UNSUCCESSFUL merging.
                    // Return the original copy of the signatures object.
                    return copySignatures;
                }
            }
            if (signatures.size() < signaturesSize) {
                // If there is a concatenation, we check again from index 0
                signaturesSize = signatures.size();
                first = 0;
            } else {
                signaturesSize = signatures.size();
                first++;
            }

        }
        return signatures;
    }

    /**
     * Clean up null values in in {@code List} of {@code List} of {@code List} of {@code PcapPacket} objects.
     * @param signature A {@link List} of {@link List} of {@link List} of
     *          {@link PcapPacket} objects that needs to be cleaned up from null values.
     */
    public static void cleanSignature(List<List<List<PcapPacket>>> signature) {

        for(List<List<PcapPacket>> listOfListPcap : signature) {
            for(List<PcapPacket> listOfPcap : listOfListPcap) {
                listOfPcap.removeIf(el -> el == null);
            }
        }
    }

        /**
         * Deep copy to create an entirely new {@link List} of {@link List} of {@link List} of {@link PcapPacket} objects.
         * @param destList A {@link List} of {@link List} of {@link List} of
         *          {@link PcapPacket} objects that will be the final container of the deep copy
         * @param sourceList A {@link List} of {@link List} of {@link List} of
         *          {@link PcapPacket} objects that will be the source of the deep copy.
         */
    private static void listDeepCopy(List<List<List<PcapPacket>>> destList, List<List<List<PcapPacket>>> sourceList) {

        for(List<List<PcapPacket>> llPcapPacket : sourceList) {
            List<List<PcapPacket>> tmpListOfList = new ArrayList<>();
            for(List<PcapPacket> lPcapPacket : llPcapPacket) {
                List<PcapPacket> tmpList = new ArrayList<>();
                for(PcapPacket pcapPacket : lPcapPacket) {
                    tmpList.add(pcapPacket);
                }
                tmpListOfList.add(tmpList);
            }
            destList.add(tmpListOfList);
        }
    }

    /**
     * Sort the sequences in the {@code List} of {@code List} of {@code List} of {@code PcapPacket} objects.
     * The purpose of this is to sort the order of sequences in the sequence list. For detection purposes, we need
     * to know if one sequence occurs earlier/later in time with respect to the other sequences for more confidence
     * in detecting the occurrence of an event.
     * @param signatures A {@code List} of {@code List} of {@code List} of {@code PcapPacket} objects that needs sorting.
     *                   We assume that innermost {@code List} of {@code PcapPacket} objects have been sorted ascending
     *                   by timestamps. By the time we use this method, we should have sorted it when calling the
     *                   {@code clusterToListOfPcapPackets} method.
     * @return A sorted {@code List} of {@code List} of {@code List} of {@code PcapPacket} objects.
     */
    public static List<List<List<PcapPacket>>> sortSequences(List<List<List<PcapPacket>>> signatures) {
        // TODO: This is the simplest solution!!! Might not cover all corner cases.
        // TODO: Sort the list of lists based on the first packet's timestamps!
    //    Collections.sort(signatures, (p1, p2) -> {
    //        //return p1.get(0).get(0).getTimestamp().compareTo(p2.get(0).get(0).getTimestamp());
    //        int compare = p1.get(0).get(0).getTimestamp().compareTo(p2.get(0).get(0).getTimestamp());
    //        return compare;
    //    });
        // TODO: The following is a more complete solution that covers corner cases.
        // Sort the list of lists based on one-to-one comparison between timestamps of signatures on both lists.
        // This also takes into account the fact that the number of signatures in the two lists could be different.
        // Additionally, this code forces the comparison between two signatures only if they occur in the
        // INCLUSION_WINDOW_MILLIS window; otherwise, it tries to find the right pair of signatures in the time window.
        Collections.sort(signatures, (p1, p2) -> {
            int compare = 0;
            int comparePrev = 0;
            int count1 = 0;
            int count2 = 0;
            // Need to make sure that both are not out of bound!
            while (count1 + 1 < p1.size() && count2 + 1 < p2.size()) {
                long timestamp1 = p1.get(count1).get(0).getTimestamp().toEpochMilli();
                long timestamp2 = p2.get(count2).get(0).getTimestamp().toEpochMilli();
                // The two timestamps have to be within a 15-second window!
                if (Math.abs(timestamp1 - timestamp2) < TriggerTrafficExtractor.INCLUSION_WINDOW_MILLIS) {
                    // If these two are within INCLUSION_WINDOW_MILLIS window then compare!
                    compare = p1.get(count1).get(0).getTimestamp().compareTo(p2.get(count2).get(0).getTimestamp());
                    overlapChecking(compare, comparePrev, p1.get(count1), p2.get(count2),
                            signatures.indexOf(p1), signatures.indexOf(p2));
                    comparePrev = compare;
                    count1++;
                    count2++;
                } else {
                    // If not within INCLUSION_WINDOW_MILLIS window then find the correct pair
                    // by incrementing one of them.
                    if (timestamp1 < timestamp2)
                        count1++;
                    else
                        count2++;
                }
                // For Pack count
                /*
                compare = p1.get(count1).get(0).getTimestamp().compareTo(p2.get(count2).get(0).getTimestamp());
                    overlapChecking(compare, comparePrev, p1.get(count1), p2.get(count2),
                            signatures.indexOf(p1), signatures.indexOf(p2));
                    comparePrev = compare;
                    count1++;
                    count2++;
                */
            }
            return compare;
        });
        return signatures;
    }

    /**
     * Checks for overlapping between two packet sequences.
     * @param compare Current comparison value between packet sequences p1 and p2
     * @param comparePrev Previous comparison value between packet sequences p1 and p2
     * @param sequence1 The packet sequence ({@link List} of {@link PcapPacket} objects).
     * @param sequence2 The packet sequence ({@link List} of {@link PcapPacket} objects).
     * @param indexSequence1 The index of packet sequence ({@link List} of {@link PcapPacket} objects).
     * @param indexSequence2 The index of packet sequence ({@link List} of {@link PcapPacket} objects).
     */
    private static void overlapChecking(int compare, int comparePrev,
                                        List<PcapPacket> sequence1, List<PcapPacket> sequence2,
                                        int indexSequence1, int indexSequence2) {

        // Check if p1 occurs before p2 but both have same overlap
        if (comparePrev != 0) { // First time since it is 0
            if (Integer.signum(compare) != Integer.signum(comparePrev)) {
                // Throw an exception if the order of the two signatures is not consistent,
                // E.g., 111, 222, 333 in one occassion and 222, 333, 111 in the other.
                throw new Error("OVERLAP WARNING: " + "" +
                        "Two sequences have some overlap. Please remove one of the sequences: " +
                        sequence1.get(0).length() + "... OR " +
                        sequence2.get(0).length() + "...");
            }
        }
        // Check if p1 is longer than p2 and p2 occurs during the occurrence of p1
        int lastIndexOfSequence1 = sequence1.size() - 1;
        // Check if the last index is null
        while (sequence1.get(lastIndexOfSequence1) == null)
            lastIndexOfSequence1--;
        int lastIndexOfSequence2 = sequence2.size() - 1;
        // Check if the last index is null
        while (sequence2.get(lastIndexOfSequence2) == null)
            lastIndexOfSequence2--;
        int compareLast =
                sequence1.get(lastIndexOfSequence1).getTimestamp().compareTo(sequence2.get(lastIndexOfSequence2).getTimestamp());
        // Check the signs of compare and compareLast
        if ((compare <= 0 && compareLast > 0) ||
            (compareLast <= 0 && compare > 0)) {
            mOverlapCounter++;
            // TODO: Probably not the best approach but we consider overlap if it happens more than once
            if (mOverlapCounter > 1) {
                throw new Error("OVERLAP WARNING: " + "" +
                        "One sequence is in the other. Please remove one of the sequences: " +
                        sequence1.get(0).length() + "... OR " +
                        sequence2.get(0).length() + "...");
            }
        }

    }

    /**
     * Gets the {@link IpV4Packet} contained in {@code packet}, or throws a {@link NullPointerException} if
     * {@code packet} does not contain an {@link IpV4Packet}.
     * @param packet A {@link PcapPacket} that is expected to contain an {@link IpV4Packet}.
     * @return The {@link IpV4Packet} contained in {@code packet}.
     * @throws NullPointerException if {@code packet} does not encapsulate an {@link IpV4Packet}.
     */
    private static IpV4Packet getIpV4PacketOrThrow(PcapPacket packet) {
        return Objects.requireNonNull(packet.get(IpV4Packet.class), "not an IPv4 packet");
    }

    /**
     * Gets the {@link EthernetPacket} contained in {@code packet}, or throws a {@link NullPointerException} if
     * {@code packet} does not contain an {@link EthernetPacket}.
     * @param packet A {@link PcapPacket} that is expected to contain an {@link EthernetPacket}.
     * @return The {@link EthernetPacket} contained in {@code packet}.
     * @throws NullPointerException if {@code packet} does not encapsulate an {@link EthernetPacket}.
     */
    private static final EthernetPacket getEthernetPacketOrThrow(PcapPacket packet) {
        return Objects.requireNonNull(packet.get(EthernetPacket.class), "not an Ethernet packet");
    }

    /**
     * Print signatures in {@code List} of {@code List} of {@code List} of {@code PcapPacket} objects.
     *
     * @param signatures A {@link List} of {@link List} of {@link List} of
     *          {@link PcapPacket} objects that needs to be printed.
     * @param resultsWriter PrintWriter object to write into log file.
     * @param printToOutput Boolean to decide whether to print out to screen or just log file.
     */
    public static void printSignatures(List<List<List<PcapPacket>>> signatures, PrintWriter resultsWriter, boolean
                                       printToOutput) {

        // Iterate over the list of all clusters/sequences
        int sequenceCounter = 0;
        for(List<List<PcapPacket>> listListPcapPacket : signatures) {
            // Iterate over every member of a cluster/sequence
            PrintWriterUtils.print("====== SEQUENCE " + ++sequenceCounter, resultsWriter, printToOutput);
            PrintWriterUtils.println(" - " + listListPcapPacket.size() + " MEMBERS ======", resultsWriter,
                    printToOutput);
            for(List<PcapPacket> listPcapPacket : listListPcapPacket) {
                // Print out packet lengths in a sequence
                int packetCounter = 0;
                for(PcapPacket pcapPacket : listPcapPacket) {
                    if(pcapPacket != null) {
                        String srcIp = pcapPacket.get(IpV4Packet.class).getHeader().getSrcAddr().getHostAddress();
                        String dstIp = pcapPacket.get(IpV4Packet.class).getHeader().getDstAddr().getHostAddress();
                        String direction = srcIp.startsWith("10.") || srcIp.startsWith("192.168.") ?
                                "(C-" : "(S-";
                        direction = dstIp.startsWith("10.") || dstIp.startsWith("192.168.") ?
                                direction + "C)" : direction + "S)";
                        PrintWriterUtils.print(pcapPacket.length() + direction, resultsWriter, printToOutput);
                    }
                    if(packetCounter < listPcapPacket.size() - 1) {
                        // Provide space if not last packet
                        PrintWriterUtils.print(" ", resultsWriter, printToOutput);
                    } else {
                        // Newline if last packet
                        PrintWriterUtils.println("", resultsWriter, printToOutput);
                    }
                    packetCounter++;
                }
            }
        }
    }

    /**
     * Extract core point range in the form of {@code List} of {@code List} of {@code PcapPacket} objects.
     *
     * @param pairs The pairs for core points extraction.
     * @param eps Epsilon value for the DBSCAN algorithm.
     * @param minPts minPts value for the DBSCAN algorithm.
     * @return A {@link List} of {@link List} of {@code PcapPacket} objects that contains core points range
     *          in the first and second element.
     */
    public static List<List<PcapPacket>> extractRangeCorePoints(List<List<PcapPacket>> pairs, double eps, int minPts) {

        // Initialize min and max value
        PcapPacket minFirstElement = null;
        PcapPacket maxFirstElement = null;
        PcapPacket minSecondElement = null;
        PcapPacket maxSecondElement = null;

        // Iterate over pairs
        for(List<PcapPacket> pair : pairs) {
            if (isCorePoint(pair, pairs, eps, minPts)) {
                // Record the first element
                if (minFirstElement == null || pair.get(0).length() < minFirstElement.length()) {
                    minFirstElement = pair.get(0);
                }
                if (maxFirstElement == null || pair.get(0).length() > maxFirstElement.length()) {
                    maxFirstElement = pair.get(0);
                }
                // Record the second element
                if (minSecondElement == null || pair.get(1).length() < minSecondElement.length()) {
                    minSecondElement = pair.get(1);
                }
                if (maxSecondElement == null || pair.get(1).length() > maxSecondElement.length()) {
                    maxSecondElement = pair.get(1);
                }
            }
        }
        List<PcapPacket> corePointLowerBound = new ArrayList<>();
        corePointLowerBound.add(0, minFirstElement);
        corePointLowerBound.add(1, minSecondElement);
        List<PcapPacket> corePointUpperBound = new ArrayList<>();
        corePointUpperBound.add(0, maxFirstElement);
        corePointUpperBound.add(1, maxSecondElement);
        // Combine lower and upper bounds
        List<List<PcapPacket>> listRangeCorePoints = new ArrayList<>();
        listRangeCorePoints.add(corePointLowerBound);
        listRangeCorePoints.add(corePointUpperBound);

        return listRangeCorePoints;
    }

    /**
     * Test whether the {@code List} of {@code PcapPacket} objects is a core point.
     *
     * @param pair The pair to be tested.
     * @param pairs All of the pairs.
     * @param eps Epsilon value for the DBSCAN algorithm.
     * @param minPts minPts value for the DBSCAN algorithm.
     * @return True if the pair is a core point.
     */
    private static boolean isCorePoint(List<PcapPacket> pair, List<List<PcapPacket>> pairs, double eps, int minPts) {

        int corePoints = 0;
        int x1 = pair.get(0) == null ? 0 : pair.get(0).length();
        int y1 = pair.get(1) == null ? 0 : pair.get(1).length();
        // Check if we have enough core points
        for(List<PcapPacket> pairInPairs : pairs) {
            int x2 = pairInPairs.get(0) == null ? 0 : pairInPairs.get(0).length();
            int y2 = pairInPairs.get(1) == null ? 0 : pairInPairs.get(1).length();
            // Measure distance between x and y
            double distance = Math.sqrt(Math.pow((double)(x2 - x1), 2) + Math.pow((double)(y2 - y1), 2));
            // Increment core points count if this point is within eps
            if (distance <= eps) {
                corePoints++;
            }
        }
        // Return true if the number of core points >= minPts
        if (corePoints >= minPts) {
            return true;
        }

        return false;
    }

    /**
     * Test the conservativeness of the signatures (basically whether we want strict or range-based matching).
     * We go for a conservative approach (strict matching) when there is no range or there are ranges but the
     * ranges overlap across multiple signatures, e.g., ON and OFF signatures.
     *
     * @param signature The signature we want to check and overwrite if needed.
     * @param eps Epsilon value for the DBSCAN algorithm.
     * @param otherSignatures Other signatures we want to check against this signature.
     * @return A boolean that is True when range-based matching is used.
     */
    public static boolean isRangeBasedMatching(List<List<List<PcapPacket>>> signature, double eps,
                                                List<List<List<List<PcapPacket>>>> otherSignatures) {
        // Check against multiple signatures
        // TODO: Per March 2019 we only support ON and OFF signatures though
        for(List<List<List<PcapPacket>>> otherSig : otherSignatures) {
            // Do conservative strict matching if there is any overlap
            if (isConservativeChecking(signature, otherSig, eps)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Test the conservativeness of the signatures (basically whether we want strict or range-based matching).
     * We go for a conservative approach (strict matching) when there is no range or there are ranges but the
     * ranges overlap across multiple signatures, e.g., ON and OFF signatures.
     *
     * @param signature The signature we want to check and overwrite if needed.
     * @param corePointRange The core points range of this signature.
     * @return A boolean that is True when range-based matching is used.
     */
    public static List<List<List<PcapPacket>>> useRangeBasedMatching(List<List<List<PcapPacket>>> signature,
                                                                     List<List<List<PcapPacket>>> corePointRange) {
        // Do range-based checking instead if there is no overlap
        // Transform our signature into a range-based format
        List<List<List<PcapPacket>>> rangeBasedSignature = getSequenceRanges(signature);
        // We have to iterate sequence by sequence in the signature that has already gone through concatenation/merging
        // And compare the packet lengths against the ones in corePointRange that are still in pairs/points
        List<List<List<PcapPacket>>> finalSignature = new ArrayList<>();

        // Construct the range-based signature
        for(List<List<PcapPacket>> listOfSequences : rangeBasedSignature) {
            List<PcapPacket> sequenceLowerBound = listOfSequences.get(0);
            List<PcapPacket> sequenceUpperBound = listOfSequences.get(1);
            List<List<PcapPacket>> newList = new ArrayList<>();
            List<PcapPacket> newListLowerBound = new ArrayList<>();
            List<PcapPacket> newListUpperBound = new ArrayList<>();
            // Iterate over the packets
            for(PcapPacket lowerBound : sequenceLowerBound) {
                // Look for the lower and upper bounds from the signature
                PcapPacket upperBound = sequenceUpperBound.get(sequenceLowerBound.indexOf(lowerBound));
                // Look for the lower and upper bounds from the cluster analysis (core point range)
                List<PcapPacket> bounds = getCorePointBounds(corePointRange, lowerBound, upperBound);
                // Add into list
                // The first element is the lower bound and the second element is the upper bound
                newListLowerBound.add(bounds.get(0));
                newListUpperBound.add(bounds.get(1));
            }
            newList.add(0, newListLowerBound);
            newList.add(1, newListUpperBound);
            finalSignature.add(newList);
        }

        return finalSignature;
    }

    /*
     * Get the corresponding PcapPacket object for lower and upper bounds.
     */
    private static List<PcapPacket> getCorePointBounds(List<List<List<PcapPacket>>> corePointRange,
                                                       PcapPacket lowerBound, PcapPacket upperBound) {

        List<PcapPacket> listBounds = new ArrayList<>();
        // Just return the lower and upper bounds when their values are the same --- faster
        if (lowerBound.length() == upperBound.length()) {
            listBounds.add(0, lowerBound);
            listBounds.add(1, upperBound);
            return listBounds;
        }
        // Iterate over PcapPacket one by one
        for(List<List<PcapPacket>> listOfListPcapPacket : corePointRange) {
            List<PcapPacket> listCorePointLowerBound = listOfListPcapPacket.get(0);
            List<PcapPacket> listCorePointUpperBound = listOfListPcapPacket.get(1);
            for(PcapPacket corePointLowerBound : listCorePointLowerBound) {
                if (corePointLowerBound == null) { // Skip if null!
                    continue;
                }
                PcapPacket corePointUpperBound =
                        listCorePointUpperBound.get(listCorePointLowerBound.indexOf(corePointLowerBound));
                // Return if the match for the core point bounds is found
                // Basically the core point range has to be within the signature range
                if (lowerBound.length() <= corePointLowerBound.length() &&
                    corePointUpperBound.length() <= upperBound.length()) {
                    listBounds.add(0, corePointLowerBound);
                    listBounds.add(1, corePointUpperBound);
                    return listBounds;
                }
                // Just skip the null elements
                if (lowerBound == null && upperBound == null) {
                    continue;
                }
            }
        }
        // Return null if not found
        return null;
    }

    /**
     * Check if there is any overlap between the signature stored in this class and another signature.
     * Conditions:
     * 1) If both signatures do not have any range, then we need to do conservative checking (return true).
     * 2) If both signatures have the same number of packets/packet lengths, then we check the range; if the
     *    numbers of packets/packet lengths are different then we assume that there is no overlap.
     * 3) If there is any range in the signatures, then we need to check for overlap.
     * 4) If there is overlap for EVERY packet/packet length, then we return true (conservative checking);
     *    otherwise false (range-based checking).
     *
     * @param signature A {@code List} of {@code List} of {@code List} of {@code PcapPacket} objects to be checked
     *                  for overlaps with the other signature.
     * @param otherSignature A {@code List} of {@code List} of {@code List} of {@code PcapPacket} objects to be checked
     *                       for overlaps with the signature.
     * @param eps Epsilon value for the DBSCAN algorithm.
     * @return A boolean that is true if there is an overlap; false otherwise.
     */
    public static boolean isConservativeChecking(List<List<List<PcapPacket>>> signature,
                                                 List<List<List<PcapPacket>>> otherSignature,
                                                 double eps) {

        // Get the ranges of the two signatures
        List<List<List<PcapPacket>>> signatureRanges = getSequenceRanges(signature);
        List<List<List<PcapPacket>>> otherSignatureRanges = getSequenceRanges(otherSignature);
        if (signature.size() == 1 && signature.get(0).get(0).size() == 2) {
            // The signature only has 2 packets
            return true;
        } else if (!isRangeBased(signatureRanges) && !isRangeBased(otherSignatureRanges)) {
            // Conservative checking when there is no range
            return true;
        } else if(signatureRanges.size() != otherSignatureRanges.size()) {
            // The two signatures have different numbers of packets/packet lengths
            return false;
        } else {
            // There is range; check if there is overlap
            return checkOverlap(signatureRanges, otherSignatureRanges, eps);
        }
    }

    /* Find the sequence with the minimum packet lengths.
     * The second-layer list should contain the minimum sequence for element 0 and maximum sequence for element 1.
     */
    private static List<List<List<PcapPacket>>> getSequenceRanges(List<List<List<PcapPacket>>> signature) {

        // Start from the first index
        List<List<List<PcapPacket>>> rangeBasedSequence = new ArrayList<>();
        for(List<List<PcapPacket>> listListPcapPacket : signature) {
            List<List<PcapPacket>> minMaxSequence = new ArrayList<>();
            // Both searches start from index 0
            List<PcapPacket> minSequence = new ArrayList<>(listListPcapPacket.get(0));
            List<PcapPacket> maxSequence = new ArrayList<>(listListPcapPacket.get(0));
            for(List<PcapPacket> listPcapPacket : listListPcapPacket) {
                for(PcapPacket pcapPacket : listPcapPacket) {
                    int index = listPcapPacket.indexOf(pcapPacket);
                    // Set the new minimum if length at the index is minimum
                    if (pcapPacket.length() < minSequence.get(index).length()) {
                        minSequence.set(index, pcapPacket);
                    }
                    // Set the new maximum if length at the index is maximum
                    if (pcapPacket.length() > maxSequence.get(index).length()) {
                        maxSequence.set(index, pcapPacket);
                    }
                }
            }
            // minSequence as element 0 and maxSequence as element 1
            minMaxSequence.add(minSequence);
            minMaxSequence.add(maxSequence);
            rangeBasedSequence.add(minMaxSequence);
        }

        return rangeBasedSequence;
    }

    /*
     * Check for overlap since we have range in at least one of the signatures.
     * Overlap is only true when all ranges overlap. We need to check in order.
     */
    private static boolean checkOverlap(List<List<List<PcapPacket>>> signatureRanges,
                                 List<List<List<PcapPacket>>> otherSignatureRanges, double eps) {

        for(List<List<PcapPacket>> listListPcapPacket : signatureRanges) {
            // Lower bound of the range is in index 0
            // Upper bound of the range is in index 1
            int sequenceSetIndex = signatureRanges.indexOf(listListPcapPacket);
            List<PcapPacket> minSequenceSignature = listListPcapPacket.get(0);
            List<PcapPacket> maxSequenceSignature = listListPcapPacket.get(1);
            for(PcapPacket pcapPacket : minSequenceSignature) {
                // Get the lower and upper bounds of the current signature
                int packetIndex = minSequenceSignature.indexOf(pcapPacket);
                int lowerBound = pcapPacket.length();
                int upperBound = maxSequenceSignature.get(packetIndex).length();
                // Check for range overlap in the other signature!
                // Check the packet/packet length at the same position
                List<PcapPacket> minSequenceSignatureOther = otherSignatureRanges.get(sequenceSetIndex).get(0);
                List<PcapPacket> maxSequenceSignatureOther = otherSignatureRanges.get(sequenceSetIndex).get(1);
                int lowerBoundOther = minSequenceSignatureOther.get(packetIndex).length();
                int upperBoundOther = maxSequenceSignatureOther.get(packetIndex).length();
                if (!(lowerBoundOther-(int)eps <= lowerBound && lowerBound <= upperBoundOther+(int)eps) &&
                    !(lowerBoundOther-(int)eps <= upperBound && upperBound <= upperBoundOther+(int)eps)) {
                    return false;
                }
            }
        }

        return true;
    }

    /*
     * Check and see if there is any range in the signatures
     */
    private static boolean isRangeBased(List<List<List<PcapPacket>>> signatureRanges) {

        for(List<List<PcapPacket>> listListPcapPacket : signatureRanges) {
            // Lower bound of the range is in index 0
            // Upper bound of the range is in index 1
            List<PcapPacket> minSequence = listListPcapPacket.get(0);
            List<PcapPacket> maxSequence = listListPcapPacket.get(1);
            for(PcapPacket pcapPacket : minSequence) {
                int index = minSequence.indexOf(pcapPacket);
                if (pcapPacket.length() != maxSequence.get(index).length()) {
                    // If there is any packet length that differs in the minSequence
                    // and maxSequence, then it is range-based
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Remove a sequence in a signature object.
     *
     * @param signatures A {@link List} of {@link List} of {@link List} of
     *          {@link PcapPacket} objects.
     * @param sequenceIndex An index for a sequence that consists of {{@link List} of {@link List} of
     *          {@link PcapPacket} objects.
     */
    public static void removeSequenceFromSignature(List<List<List<PcapPacket>>> signatures, int sequenceIndex) {

        // Sequence index starts from 0
        signatures.remove(sequenceIndex);
    }

    /**
     * Convert a String MAC address into a byte array.
     *
     * @param macAddress A String that contains a MAC address to be converted into byte array.
     */
    public static byte[] stringToByteMacAddress(String macAddress) {

        BigInteger biMacAddress = new BigInteger(macAddress, 16);
        byte[] byteMacAddress = biMacAddress.toByteArray();
        // Return from 1 to 6 since element 0 is 0 because of using BigInteger's method.
        return Arrays.copyOfRange(byteMacAddress, 1, 7);
    }
}
