package edu.uci.iotproject.detection;

import org.pcap4j.core.PcapPacket;

import java.util.List;

/**
 * Used for registering for notifications from a signature detector.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public interface SignatureDetectorObserver {

    /**
     * Invoked when the signature detector has detected the presence of a signature in the traffic that it's examining.
     * @param searchedSignature The signature that the signature detector reporting the match is searching for.
     * @param matchingTraffic The actual traffic trace that matches the searched signature.
     */
    void onSignatureDetected(List<List<List<PcapPacket>>> searchedSignature, List<List<PcapPacket>> matchingTraffic);

}
