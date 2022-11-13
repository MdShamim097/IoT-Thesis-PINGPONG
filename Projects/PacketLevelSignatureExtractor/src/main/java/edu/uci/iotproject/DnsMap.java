package edu.uci.iotproject;

import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsResourceRecord;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;


import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.*;


/**
 * This is a class that does DNS mapping.
 * Basically an IP address is mapped to its
 * respective DNS hostnames.
 *
 * @author Rahmadi Trimananda (rtrimana@uci.edu)
 * @version 0.1
 */
public class DnsMap implements PacketListener {

    /* Class properties */
    private Map<String, Set<String>> ipToHostnameMap;

    /* Class constants */
    private static final Set<String> EMPTY_SET = Collections.unmodifiableSet(new HashSet<>());

    
    /* Constructor */
    public DnsMap() {
        ipToHostnameMap = new HashMap<>();
    }

    @Override
    public void gotPacket(PcapPacket packet) {
        try {
            validateAndAddNewEntry(packet);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }

    /**
     * Gets a packet and determine if this is a DNS packet
     *
     * @param   packet  Packet object
     * @return          DnsPacket object or null
     */
    private DnsPacket getDnsPacket(Packet packet) {
        DnsPacket dnsPacket = packet.get(DnsPacket.class);
        return dnsPacket;
    }

    /**
     * Checks DNS packet and build the map data structure that
     * maps IP addresses to DNS hostnames
     *
     * @param   packet  PcapPacket object
     */
    public void validateAndAddNewEntry(PcapPacket packet) throws UnknownHostException {
        // Make sure that this is a DNS packet
        DnsPacket dnsPacket = getDnsPacket(packet);
        if (dnsPacket != null) {
            // We only care about DNS answers
            if (dnsPacket.getHeader().getAnswers().size() != 0) {
                String hostname = dnsPacket.getHeader().getQuestions().get(0).getQName().getName();
                for(DnsResourceRecord answer : dnsPacket.getHeader().getAnswers()) {
                    // We only care about type A records
                    if (!answer.getDataType().equals(DnsResourceRecordType.A))
                        continue;
                    // Sanity check. For some reason the hostname appears to be the empty string in the answer .
                    // We hence have to assume that all answers correspond to a single question that holds the hostname as part of its object tree.
                    // Therefore, if there are more questions in one query-reply exchange, we are in trouble.
                    if (!answer.getName().getName().equals("") && !answer.getName().getName().equals(hostname))
                        throw new RuntimeException("[DNS parser] mismatch between hostname in question and hostname in answer");
                    // The IP in byte representation.
                    byte[] ipBytes = answer.getRData().getRawData();
                    // Convert to string representation.
                    String ip = Inet4Address.getByAddress(ipBytes).getHostAddress();
                    Set<String> hostnameSet = new HashSet<>();
                    hostnameSet.add(hostname);
                    // Update or insert depending on presence of key:
                    // Concat the existing set and the new set if ip already present as key,
                    // otherwise add an entry for ip pointing to new set.
                    ipToHostnameMap.merge(ip, hostnameSet, (v1, v2) -> { v1.addAll(v2); return v1; });
                }
            }
        }
    }
    
    
    /**
     * Checks DNS packet and build the map data structure that
     * maps IP addresses to DNS hostnames
     *
     * @param   address     Address to check
     * @param   hostname    Hostname to check
     */
    public boolean isRelatedToCloudServer(String address, String hostname) {
        return ipToHostnameMap.getOrDefault(address, EMPTY_SET).contains(hostname);
    }

    public Set<String> getHostnamesForIp(String ip) {
        Set<String> hostnames = ipToHostnameMap.get(ip);
        return hostnames != null ? Collections.unmodifiableSet(hostnames) : null;
    }
}
