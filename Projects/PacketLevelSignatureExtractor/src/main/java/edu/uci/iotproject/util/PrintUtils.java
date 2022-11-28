package edu.uci.iotproject.util;

import edu.uci.iotproject.DnsMap;
import edu.uci.iotproject.analysis.PcapPacketPair;
import org.apache.commons.math3.stat.clustering.Cluster;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.pcap4j.core.PcapPacket;

/**
 * Utility methods for generating (output) strings.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class PrintUtils {

    /**
     * This is the path for writing the list of list of packet pairs {@code List<List<PcapPacket>>} into a file.
     * The packet pairs are the pairs in one cluster, so the list represents a cluster that has been derived through
     * the DBSCAN algorithm.
     *
     * E.g., this file could contain a list like the following:
     *
     * [[1109, 613],[1111, 613],[1115, 613],...]
     *
     * This list has lists of PcapPacket pairs as its members. We do not maintain the pairs in the form of
     * {@code Cluster<PcapPacketPair>} objects because there might be a situation where we could combine multiple
     * PcapPacketPair objects into a longer signature, i.e., a string of PcapPacket objects and not just a pair.
     */
    private static final String SERIALIZABLE_FILE_PATH = "./signature.sig";

    private PrintUtils() { /* private constructor to prevent instantiation */ }

    /**
     * Write the list of list of packet pairs {@code List<List<PcapPacket>>} into a file.
     *
     * After the DBSCAN algorithm derives the clusters from pairs, we save the signature in the form of list of
     * packet pairs. We harvest the pairs and transform them back into a list of PcapPacket objects.
     * We do not maintain the pairs in the form of {@code Cluster<PcapPacketPair>} objects because there might be
     * a situation where we could combine multiple PcapPacketPair objects into a longer signature, i.e., a string of
     * PcapPacket objects and not just a pair.
     *
     * @param fileName The path of the file in {@link String}. We could leave this one {@code null} if we wanted the
     *                 default file name {@code SERIALIZABLE_FILE_PATH}.
     * @param clusterPackets The {@link Cluster} objects in the form of list of {@code PcapPacket} objects.
     */
    public static void serializeClustersIntoFile(String fileName, List<List<PcapPacket>> clusterPackets) {
        if (fileName == null)
            fileName = SERIALIZABLE_FILE_PATH;
        try (ObjectOutputStream oos =
                new ObjectOutputStream(new FileOutputStream(fileName))) {
            oos.writeObject(clusterPackets);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Write the signature and cluster analysis {@code List<List<List<PcapPacket>>>} into a file.
     *
     * After the DBSCAN algorithm derives the clusters from pairs, we save the signature and cluster analysis
     * in the form of list of packet pairs. We harvest the pairs and transform them back into a list of PcapPacket
     * objects.
     * We do not maintain the pairs in the form of {@code Cluster<PcapPacketPair>} objects because there might be
     * a situation where we could combine multiple PcapPacketPair objects into a longer signature, i.e., a string of
     * PcapPacket objects and not just a pair.
     *
     * @param fileName The path of the file in {@link String}. We could leave this one {@code null} if we wanted the
     *                 default file name {@code SERIALIZABLE_FILE_PATH}.
     * @param signature The {@link Cluster} objects in the form of list of {@code PcapPacket} objects.
     */
    public static void serializeIntoFile(String fileName, List<List<List<PcapPacket>>> signature) {
        if (fileName == null)
            fileName = SERIALIZABLE_FILE_PATH;
        try (ObjectOutputStream oos =
                     new ObjectOutputStream(new FileOutputStream(fileName))) {
            oos.writeObject(signature);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Read the list of list of packet pairs {@code List<List<PcapPacket>>} from a file.
     *
     * After the DBSCAN algorithm derives the clusters from pairs, we save the signature in the form of list of
     * packet pairs. We harvest the pairs and transform them back into a list of PcapPacket objects.
     * We do not maintain the pairs in the form of {@code Cluster<PcapPacketPair>} objects because there might be
     * a situation where we could combine multiple PcapPacketPair objects into a longer signature, i.e., a string of
     * PcapPacket objects and not just a pair.
     *
     * @param fileName The path of the file in {@link String}. We could leave this one {@code null} if we wanted the
     *                 default file name {@code SERIALIZABLE_FILE_PATH}.
     * @return The list of list of {@link Cluster} objects ({@code List<List<PcapPacket>>}) that is read from file.
     */
    public static List<List<PcapPacket>> deserializeClustersFromFile(String fileName) {
        if (fileName == null)
            fileName = SERIALIZABLE_FILE_PATH;
        List<List<PcapPacket>> ppListOfList = null;
        try (ObjectInputStream ois =
                     new ObjectInputStream(new FileInputStream(fileName))) {
            ppListOfList = (List<List<PcapPacket>>) ois.readObject();
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return ppListOfList;
    }

    /**
     * Read the list of list of packet pairs {@code List<List<List<PcapPacket>>>} from a file.
     *
     * @param fileName The path of the file in {@link String}. We could leave this one {@code null} if we wanted the
     *                 default file name {@code SERIALIZABLE_FILE_PATH}.
     * @return The list of list of list of {@link Cluster} objects ({@code List<List<List<PcapPacket>>>})
     *         that is read from file.
     */
    public static List<List<List<PcapPacket>>> deserializeFromFile(String fileName) {
        if (fileName == null)
            fileName = SERIALIZABLE_FILE_PATH;
        List<List<List<PcapPacket>>> ppListOfListOfList = null;
        try (ObjectInputStream ois =
                     new ObjectInputStream(new FileInputStream(fileName))) {
            ppListOfListOfList = (List<List<List<PcapPacket>>>) ois.readObject();
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return ppListOfListOfList;
    }

    /**
     * Converts a {@code PcapPacketPair} into a CSV string containing the packet lengths of the two packets in the pair.
     *
     * For example, the resulting string will be "123, 456" if the first packet of the pair has a length of 123 and the
     * second packet of the pair has a length of 456.
     *
     * <b>Note:</b> if the {@link PcapPacketPair} has no second element, 0 is printed as the length of the second packet
     * in the pair.
     *
     * @return a CSV string containing the packet lengths of the two packets of the given {@code PcapPacketPair}.
     */
    public static String toCsv(PcapPacketPair packetPair) {
        return String.format("%d, %d", packetPair.getFirst().getOriginalLength(),
                packetPair.getSecond().map(pp -> pp.getOriginalLength()).orElse(0));
    }

    /**
     * Converts a {@code PcapPacketPair} into a CSV string containing the packet lengths of the two packets in the pair
     * followed by the source of each packet. The source will be a (set of) hostname(s) if the source IP can be resolved
     * to a (set of) hostname(s) using the provided {@link DnsMap}.
     *
     * For example, the resulting string will be "123, 456, 192.168.1.42, domain.com" if the first packet of the pair
     * has a length of 123, the second packet of the pair has a length of 4toSummaryString56, the first packet of the pair the pair has
     * a source IP of '192.168.1.42' that cannot be resolved to a hostname, and the second packet of the pair has an IP
     * that resolves to 'domain.com'.
     *
     * <b>Note:</b> if the {@link PcapPacketPair} has no second element, 0 is printed as the length of the second packet
     * in the pair, and null is printed for its source.
     *
     * @return a CSV string containing the packet lengths of the two packets of the given {@code PcapPacketPair} as well
     *         as their respective sources.
     */
    public static String toCsv(PcapPacketPair packetPair, DnsMap ipHostnameMappings) {
        // First obtain source IPs
        String firstSrc = PcapPacketUtils.getSourceIp(packetPair.getFirst());
        // Note: use optional for second item in pair as there might not be one.
        Optional<String> secondSrc = packetPair.getSecond().map(pkt -> PcapPacketUtils.getSourceIp(pkt));

        // if(ipHostnameMappings==null){
        //     System.out.println("Got a null");
        // }
        // else{
        //     System.out.println("No null");
        // }
        // If possible, map source IPs to hostnames.
        Set<String> firstHostnames = ipHostnameMappings.getHostnamesForIp(firstSrc);
        Optional<Set<String>> secondHostnames = secondSrc.map(src -> ipHostnameMappings.getHostnamesForIp(src));
        final String delimiter = " ";
        if (firstHostnames != null) {
            // If one IP maps to multiple hostnames, we concatenate the hostnames (separated by a delimiter).
            firstSrc = firstHostnames.stream().collect(Collectors.joining(delimiter));
        }
        // If one IP maps to multiple hostnames, we concatenate the hostnames (separated by a delimiter).
        Optional<String> hostnames = secondHostnames.map(hostnameSet -> hostnameSet.stream().collect(Collectors.joining(delimiter)));
        // Fall back to IP if we couldn't second pair is present, but we couldn't map to (a) hostname(s).
        secondSrc = hostnames.isPresent() ? hostnames : secondSrc;

        // Check if the first source is C (client) or S (server).
        String firstSrcCorS = packetPair.isFirstClient() ? "C" : "S";
        String secondSrcCorS = packetPair.isSecondClient() ? "C" : "S";

        return String.format("%d, %d, %s, %s, %s, %s", packetPair.getFirst().getOriginalLength(),
                packetPair.getSecond().map(pp -> pp.getOriginalLength()).orElse(0),
                firstSrc,
                secondSrc.orElse("null"),
                firstSrcCorS,
                secondSrcCorS);
    }

    /**
     * Generate a string that summarizes/describes {@code cluster}.
     * @param cluster The {@link Cluster} to summarize/describe.
     * @return A string that summarizes/describes {@code cluster}.
     */
    public static String toSummaryString(Cluster<PcapPacketPair> cluster) {
        StringBuilder sb = new StringBuilder();
        for (PcapPacketPair ppp : cluster.getPoints()) {
            sb.append(toCsv(ppp, ppp.getDnsMap()) + System.lineSeparator());
        }
        return sb.toString();
    }
}
