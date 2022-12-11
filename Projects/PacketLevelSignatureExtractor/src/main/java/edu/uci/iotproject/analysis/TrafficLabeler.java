package edu.uci.iotproject.analysis;

import edu.uci.iotproject.trafficreassembly.layer3.Conversation;
import edu.uci.iotproject.DnsMap;
import edu.uci.iotproject.trafficreassembly.layer3.TcpReassembler;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapPacket;

import java.time.Instant;
import java.util.*;
import java.util.function.Function;

/**
 * A {@link PacketListener} that marks network traffic as (potentially) related to a user's actions by comparing the
 * timestamp of each packet to the timestamps of the provided list of user actions.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class TrafficLabeler implements PacketListener {

    private final Map<UserAction, List<PcapPacket>> mActionToTrafficMap;
    private final List<UserAction> mActionsSorted;
    /**
     * The total number of packets labeled, i.e, the sum of the sizes of the values in {@link #mActionToTrafficMap}.
     */
    private long mPackets = 0;

    public TrafficLabeler(List<UserAction> userActions) {
        // Init map with empty lists (no packets have been mapped to UserActions at the onset).
        mActionToTrafficMap = new HashMap<>();
        userActions.forEach(ua -> mActionToTrafficMap.put(ua, new ArrayList<>()));
        // Sort list of UserActions by timestamp in order to facilitate fast Packet-to-UserAction mapping.
        // For safety reasons, we create an internal copy of the list to prevent external code from changing the list's
        // contents as that would render our assumptions about order of elements invalid.
        // In addition, this also ensures that we do not break assumptions made by external code as we avoid reordering
        // the elements of the list passed from the external code.
        // If performance is to be favored over safety, assign userActions to mActionsSorted directly.
        mActionsSorted = new ArrayList<>();
        mActionsSorted.addAll(userActions);
        Collections.sort(mActionsSorted, (ua1, ua2) -> ua1.getTimestamp().compareTo(ua2.getTimestamp()));
    }


    @Override
    public void gotPacket(PcapPacket packet) {
        // Locate UserAction corresponding to packet, if any.
        int index = Collections.binarySearch(mActionsSorted, new UserAction(0, packet.getTimestamp()), (listItem, key) -> {
            // Start of inclusion interval is the time of the user action
            Instant intervalStart = listItem.getTimestamp();
            // End of inclusion interval is some arbitrary number of milliseconds after the user action.
            Instant intervalEnd = intervalStart.plusMillis(TriggerTrafficExtractor.INCLUSION_WINDOW_MILLIS);
            if (key.getTimestamp().isAfter(intervalStart)) {
            //if (key.getTimestamp().isAfter(intervalStart) && key.getTimestamp().isBefore(intervalEnd)) {
                // Packet lies within specified interval after the current UserAction, so we're done.
                // Communicate termination to binarySearch by returning 0 which indicates equality.
                return 0;
            }

            /*
            if (key.getTimestamp().isAfter(intervalStart) && mPackets<TriggerTrafficExtractor.INCLUSION_NUMBER_OF_PACKETS) {
                // Packet lies within specified interval after the current UserAction, so we're done.
                // Communicate termination to binarySearch by returning 0 which indicates equality.
                return 0;
            }
                */

            // If packet lies outside inclusion interval of current list item, continue search in lower or upper half of
            // list depending on whether the timestamp of the current list item is smaller or greater than that of the
            // packet.
            return listItem.getTimestamp().compareTo(key.getTimestamp());
        });
        if (index >= 0) {
            // Associate the packet to the its corresponding user action (located during the binary search above).
            mActionToTrafficMap.get(mActionsSorted.get(index)).add(packet);
            mPackets++;
        }
        // Ignore packet if it is not found to be in temporal proximity of a user action.
    }

    /**
     * Get the total number of packets labeled by this {@code TrafficLabeler}.
     *
     * @return the total number of packets labeled by this {@code TrafficLabeler}.
     */
    public long getTotalPacketCount() {
        return mPackets;
    }

    /**
     * Get the labeled traffic.
     *
     * @return A {@link Map} in which a {@link UserAction} points to a {@link List} of {@link PcapPacket}s believed to
     *         be related (occurring as a result of) that {@code UserAction}.
     */
    public Map<UserAction, List<PcapPacket>> getLabeledTraffic() {
        return Collections.unmodifiableMap(mActionToTrafficMap);
    }

    /**
     * Like {@link #getLabeledTraffic()}, but allows the caller to supply a mapping function that is applied to
     * the traffic associated with each {@link UserAction} (the traffic label) before returning the labeled traffic.
     * This may for example be useful for a caller who wishes to perform some postprocessing of labeled traffic, e.g.,
     * in order to perform additional filtering or to transform the representation of labeled traffic.
     * <p>
     *     An example usecase is provided in {@link #getLabeledReassembledTcpTraffic()} which uses this function to
     *     build a {@link Map} in which a {@link UserAction} points to the reassembled TCP connections believed to have
     *     occurred as a result of that {@code UserAction}.
     * </p>
     *
     * @param mappingFunction A mapping function that converts a {@link List} of {@link PcapPacket} into some other type
     *                        {@code T}.
     * @param <T> The return type of {@code mappingFunction}.
     * @return A {@link Map} in which a {@link UserAction} points to the result of applying {@code mappingFunction} to
     *         the set of packets believed to be related (occurring as a result of) that {@code UserAction}.
     */
    public <T> Map<UserAction, T> getLabeledTraffic(Function<List<PcapPacket>, T> mappingFunction) {
        Map<UserAction, T> result = new HashMap<>();
        mActionToTrafficMap.forEach((ua, packets) -> result.put(ua, mappingFunction.apply(packets)));
        return result;
    }


    /**
     * Get the labeled traffic reassembled as TCP connections (<b>note:</b> <em>discards</em> all non-TCP traffic).
     *
     * @return A {@link Map} in which a {@link UserAction} points to a {@link List} of {@link Conversation}s believed to
     *         be related (occurring as a result of) that {@code UserAction}.
     */
    public Map<UserAction, List<Conversation>> getLabeledReassembledTcpTraffic() {
        return getLabeledTraffic(packets -> {
            TcpReassembler tcpReassembler = new TcpReassembler();
            packets.forEach(p -> tcpReassembler.gotPacket(p));
            return tcpReassembler.getTcpConversations();
        });
    }

    /**
     * Like {@link #getLabeledReassembledTcpTraffic()}, but uses the provided {@code ipHostnameMappings} to group
     * {@link Conversation}s by hostname.
     *
     * @param ipHostnameMappings A {@link DnsMap} with IP to hostname mappings used for reverse DNS lookup.
     * @return A {@link Map} in which a {@link UserAction} points to the set of {@link Conversation}s believed to be
     *         related (occurring as a result of) that {@code UserAction}. More precisely, each {@code UserAction} in
     *         the returned {@code Map} points to <em>another</em> {@code Map} in which a hostname points to the set of
     *         {@code Conversation}s involving that hostname.
     */
    public Map<UserAction, Map<String, List<Conversation>>> getLabeledReassembledTcpTraffic(DnsMap ipHostnameMappings) {
        return getLabeledTraffic(packets -> {
            TcpReassembler tcpReassembler = new TcpReassembler();
            packets.forEach(p -> tcpReassembler.gotPacket(p));
            return TcpConversationUtils.groupConversationsByHostname(tcpReassembler.getTcpConversations(), ipHostnameMappings);
        });
    }

}