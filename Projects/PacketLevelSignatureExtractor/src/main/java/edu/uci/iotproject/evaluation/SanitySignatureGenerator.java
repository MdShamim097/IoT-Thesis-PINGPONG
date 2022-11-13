package edu.uci.iotproject.evaluation;

import edu.uci.iotproject.trafficreassembly.layer3.Conversation;
import edu.uci.iotproject.trafficreassembly.layer3.TcpReassembler;
import edu.uci.iotproject.io.PcapHandleReader;
import edu.uci.iotproject.util.PrintUtils;
import org.pcap4j.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Hacky utility for producing a sanity signature for negative test sets.
 * <p>
 * More precisely, given information about packet lengths and packet directions known to be present in an input trace,
 * this class locates the first occurrence of a matching sequence in the input trace and outputs it to a file in the
 * signature format (i.e., a {@code List<List<List<PcapPacket>>>}.
 * </p>
 * <p>
 *     Note: can only produce simplistic signatures, i.e., a signature that is a <em>single</em> packet sequence that
 *     occurs on a single TCP connection.
 * </p>
 *
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class SanitySignatureGenerator {

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        // The pcap file
        final String pcapPath = "/Users/varmarken/temp/UCI IoT Project/experiments/evaluation/negative-datasets/UNB/Monday-WorkingHours_one-local-endpoint.pcap";
        final String sigOutputPath = "/Users/varmarken/temp/UCI IoT Project/experiments/evaluation/negative-datasets/UNB/Monday-WorkingHours_one-local-endpoint_sanity.sig";
        // The sequence of packet lengths known to be present in the trace
        final List<Integer> pktLengths = new ArrayList<>();
        pktLengths.add(340);
        pktLengths.add(295);
        // ...and their corresponding directions
        final List<Conversation.Direction> pktDirections = new ArrayList<>();
        pktDirections.add(Conversation.Direction.CLIENT_TO_SERVER);
        pktDirections.add(Conversation.Direction.SERVER_TO_CLIENT);
        // Is the signature a TLS sequence?
        final boolean tlsSequence = false;


        PcapHandle handle;
        try {
            handle = Pcaps.openOffline(pcapPath, PcapHandle.TimestampPrecision.NANO);
        } catch (PcapNativeException pne) {
            handle = Pcaps.openOffline(pcapPath);
        }
        SequenceFinder seqFinder = new SequenceFinder(pktLengths, pktDirections, tlsSequence, sigOutputPath);
        final PcapHandleReader reader = new PcapHandleReader(handle, p -> true, seqFinder);
        seqFinder.setPcapHandleReader(reader);
        reader.readFromHandle();
    }


    private static class SequenceFinder implements PacketListener {
        private final TcpReassembler mTcpReassembler = new TcpReassembler();
        private final List<Integer> mPktLengths;
        private final List<Conversation.Direction> mPktDirections;
        private final boolean mTlsSequence;
        private PcapHandleReader mReader;
        private final String mSignatureOutputPath;

        private SequenceFinder(List<Integer> pktLengths,
                               List<Conversation.Direction> pktDirections,
                               boolean tlsSequence,
                               String sigOutputPath) {
            mPktLengths = pktLengths;
            mPktDirections = pktDirections;
            mTlsSequence = tlsSequence;
            mSignatureOutputPath = sigOutputPath;
        }

        @Override
        public void gotPacket(PcapPacket packet) {
            // Skip packets not matching expected length
            if (!mPktLengths.contains(packet.getOriginalLength())) {
                return;
            }
            // Otherwise forward to TCP reassembler.
            mTcpReassembler.gotPacket(packet);
            // We are done as soon as we have one conversation that has the expected number of packets with the expected
            // directions.
            Optional<Conversation> match = mTcpReassembler.getTcpConversations().stream().filter(c -> {
                List<PcapPacket> cPkts = mTlsSequence ? c.getTlsApplicationDataPackets() : c.getPackets();
                if (cPkts.size() != mPktLengths.size()) {
                    return false;
                }
                for (int i = 0; i < cPkts.size(); i++) {
                    if (c.getDirection(cPkts.get(i)) != mPktDirections.get(i) ||
                            cPkts.get(i).getOriginalLength() != mPktLengths.get(i)) {
                        return false;
                    }
                }
                return true;
            }).findFirst();
            if (match.isPresent()) {
                System.out.println("match found");
                // Terminate reader; no need to process the full file as we already have the data to produce the signature.
                mReader.stopReading();
                // Convert sequence to signature format.
                List<List<List<PcapPacket>>> signature = new ArrayList<>();
                List<List<PcapPacket>> cluster = new ArrayList<>();
                List<PcapPacket> sequence = mTlsSequence ? match.get().getTlsApplicationDataPackets() : match.get().getPackets();
                cluster.add(sequence);
                signature.add(cluster);
                // Output the signature to a file.
                PrintUtils.serializeIntoFile(mSignatureOutputPath, signature);
            }
        }

        private void setPcapHandleReader(PcapHandleReader reader) {
            mReader = reader;
        }
    }

}
