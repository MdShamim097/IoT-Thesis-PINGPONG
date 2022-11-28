package edu.uci.iotproject.detection.layer3;
import edu.uci.iotproject.filenaming.*;
import edu.uci.iotproject.analysis.TriggerTrafficExtractor;
import edu.uci.iotproject.analysis.UserAction;
import edu.uci.iotproject.detection.AbstractClusterMatcher;
import edu.uci.iotproject.detection.ClusterMatcherObserver;
import edu.uci.iotproject.io.PcapHandleReader;
import edu.uci.iotproject.io.PrintWriterUtils;
import edu.uci.iotproject.util.PcapPacketUtils;
import edu.uci.iotproject.util.PrintUtils;
import org.apache.commons.math3.distribution.AbstractRealDistribution;
import org.apache.commons.math3.distribution.NormalDistribution;
import org.jgrapht.GraphPath;
import org.jgrapht.alg.shortestpath.DijkstraShortestPath;
import org.jgrapht.graph.DefaultWeightedEdge;
import org.jgrapht.graph.SimpleDirectedWeightedGraph;
import org.pcap4j.core.*;

import java.io.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.Duration;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.*;
import java.util.function.Consumer;

/**
 * Detects an event signature that spans one or multiple TCP connections.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class Layer3SignatureDetector implements PacketListener, ClusterMatcherObserver {

    /**
     * If set to {@code true}, output written to the results file is also dumped to standard out.
     */
    private static boolean DUPLICATE_OUTPUT_TO_STD_OUT = true;

    /**
     * Router's IP.
     *
     * TODO: The following was the router address for EH (Networking Lab)
     * private static String ROUTER_WAN_IP = "128.195.205.105";
     */
    private static String ROUTER_WAN_IP = "128.195.55.242";

    public static void main(String[] args) throws PcapNativeException, NotOpenException, IOException {
        String errMsg = String.format("SPECTO version 1.0\n" +
                        "Copyright (C) 2018-2019 Janus Varmarken and Rahmadi Trimananda.\n" +
                        "University of California, Irvine.\n" +
                        "All rights reserved.\n\n" +
                        "Usage: %s inputPcapFile onAnalysisFile offAnalysisFile onSignatureFile offSignatureFile resultsFile" +
                        "\n  inputPcapFile: the target of the detection" +
                        "\n  AnalysisFile: the file that contains the all clusters analysis" +
                        "\n  SignatureFile: the file that contains the all signature to search for" +
                        "\n  resultsFile: where to write the results of the detection" +
                        "\n  signatureDuration: the maximum duration of signature detection" +
                        "\n  epsilon: the epsilon value for the DBSCAN algorithm\n" +
                         "\n  eventTypes: Supported events for a device" +
                        "\n  eventsOccurred: Types of the events occurred during signature generation; input must be in 0-indexed number" +
                        "\n  Additional options (add '-r' before the following two parameters):" +
                        "\n  delta: delta for relaxed matching" +
                        "\n  packetId: packet number in the sequence" +
                        "\n            (could be more than one packet whose matching is relaxed, " +
                        "\n             e.g., 0,1 for packets 0 and 1)",
                Layer3SignatureDetector.class.getSimpleName());
        if (args.length < 8) {
            System.out.println(errMsg);
            return;
        }
        final String pcapFile = args[0];
        final String ClusterAnalysisFile = args[1];
        final String SignatureFile = args[2];
        final String resultsFile = args[3];
        // TODO: THIS IS TEMPORARILY SET TO DEFAULT SIGNATURE DURATION
        // TODO: WE DO NOT WANT TO BE TOO STRICT AT THIS POINT SINCE LAYER 3 ALREADY APPLIES BACK-TO-BACK REQUIREMENT
        // TODO: FOR PACKETS IN A SIGNATURE
//        final int signatureDuration = Integer.parseInt(args[6]);    //------- difference with layer2
        final int signatureDuration = TriggerTrafficExtractor.INCLUSION_WINDOW_MILLIS;
        final double eps = Double.parseDouble(args[5]);
        final String eventTypes = args[6];
        //final String eventsOccurred = args[7]; // ----------we have an unused argumment in [7]
        
        File eventTypesFile = new File(eventTypes);
        //File eventsOccurredFile = new File(eventsOccurred);

        // Additional feature---relaxed matching
        int delta = 0;
        final Set<Integer> packetSet = new HashSet<>();
        if (args.length == 11 && args[8].equals("-r")) { //------- difference with layer2
            delta = Integer.parseInt(args[9]);
            StringTokenizer stringTokenizerOff = new StringTokenizer(args[10], ",");
            // Add the list of packet IDs
            while(stringTokenizerOff.hasMoreTokens()) {
                int id = Integer.parseInt(stringTokenizerOff.nextToken());
                packetSet.add(id);
            }
        }

        List<String> eventNames = new ArrayList();
        try (BufferedReader br = new BufferedReader(new FileReader(eventTypesFile))) {
            String s;
            while ((s = br.readLine()) != null) {
                eventNames.add(s);
            }
        }
        int n=eventNames.size();

        // Prepare file outputter.
        File outputFile = new File(resultsFile);
        outputFile.getParentFile().mkdirs();
        final PrintWriter resultsWriter = new PrintWriter(new FileWriter(outputFile));
        // Include metadata as comments at the top
        PrintWriterUtils.println("# Detection results for:", resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
        PrintWriterUtils.println("# - inputPcapFile: " + pcapFile, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
        // PrintWriterUtils.println("# - onAnalysisFile: " + onClusterAnalysisFile, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
        // PrintWriterUtils.println("# - offAnalysisFile: " + offClusterAnalysisFile, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
        // PrintWriterUtils.println("# - onSignatureFile: " + onSignatureFile, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
        // PrintWriterUtils.println("# - offSignatureFile: " + offSignatureFile, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);

        for(int i=0;i<n;i++)
        {
            String fname = Naming.getName(ClusterAnalysisFile,eventNames.get(i));
            PrintWriterUtils.println("# - " + eventNames.get(i) +"AnalysisFile: " + fname, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
        }

        for(int i=0;i<n;i++)
        {
            String fname = Naming.getName(SignatureFile,eventNames.get(i));
            PrintWriterUtils.println("# - " + eventNames.get(i) +"SignatureFile: " + fname, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
        }

        resultsWriter.flush();

        // // Load signatures
        // List<List<List<PcapPacket>>> onSignature = PrintUtils.deserializeFromFile(onSignatureFile);
        // List<List<List<PcapPacket>>> offSignature = PrintUtils.deserializeFromFile(offSignatureFile);
        // // Load signature analyses
        // List<List<List<PcapPacket>>> onClusterAnalysis = PrintUtils.deserializeFromFile(onClusterAnalysisFile);
        // List<List<List<PcapPacket>>> offClusterAnalysis = PrintUtils.deserializeFromFile(offClusterAnalysisFile);

        List<List<List<List<PcapPacket>>>> Signature = new ArrayList<> ();
        for(int i=0;i<n;i++)
        {
            String fname = Naming.getName(SignatureFile,eventNames.get(i));
            List<List<List<PcapPacket>>> curr = PrintUtils.deserializeFromFile(fname);
            Signature.add(curr);

        }

        List<List<List<List<PcapPacket>>>> ClusterAnalysis = new ArrayList<> ();
        for(int i=0;i<n;i++)
        {
            String fname = Naming.getName(ClusterAnalysisFile,eventNames.get(i));
            List<List<List<PcapPacket>>> curr = PrintUtils.deserializeFromFile(fname);
            ClusterAnalysis.add(curr);

        }

        // TODO: FOR NOW WE DECIDE PER SIGNATURE AND THEN WE OR THE BOOLEANS
        // TODO: SINCE WE ONLY HAVE 2 SIGNATURES FOR NOW (ON AND OFF), THEN IT IS USUALLY EITHER RANGE-BASED OR
        // TODO: STRICT MATCHING
        // Check if we should use range-based matching
        // boolean isRangeBasedForOn = PcapPacketUtils.isRangeBasedMatching(onSignature, eps, offSignature);
        // boolean isRangeBasedForOff = PcapPacketUtils.isRangeBasedMatching(offSignature, eps, onSignature);
        // // Update the signature with ranges if it is range-based
        // if (isRangeBasedForOn) {
        //     onSignature = PcapPacketUtils.useRangeBasedMatching(onSignature, onClusterAnalysis);
        // }
        // if (isRangeBasedForOff) {
        //     offSignature = PcapPacketUtils.useRangeBasedMatching(offSignature, offClusterAnalysis);
        // }
        // // WAN
        // Layer3SignatureDetector onDetector = new Layer3SignatureDetector(onSignature, ROUTER_WAN_IP,
        //         signatureDuration, isRangeBasedForOn, eps, delta, packetSet);
        // Layer3SignatureDetector offDetector = new Layer3SignatureDetector(offSignature, ROUTER_WAN_IP,
        //         signatureDuration, isRangeBasedForOff, eps, delta, packetSet);

        List<Layer3SignatureDetector> Detector = new ArrayList<>();
        final List<UserAction> detectedEvents = new ArrayList<>(); //---updated on 27/11/2022
        for(int i=0;i<n;i++)
        {
            final int var=i;
            List<List<List<List<PcapPacket>>>> otherSignatures = new ArrayList<>();
            for(int j=0;j<n;j++)
            {
                if(j==i) continue;
                otherSignatures.add(Signature.get(j));
            }
            boolean isRangeBasedForCurrent = PcapPacketUtils.isRangeBasedMatching(Signature.get(i), eps, otherSignatures);
            List<List<List<PcapPacket>>> currentSignature = Signature.get(i);
            if (isRangeBasedForCurrent) {
                currentSignature = PcapPacketUtils.useRangeBasedMatching(currentSignature, ClusterAnalysis.get(i));
            }

            //WAN    //-------difference with layer2
            Layer3SignatureDetector currentDetector = new Layer3SignatureDetector(currentSignature, ROUTER_WAN_IP,
                 signatureDuration, isRangeBasedForCurrent, eps, delta, packetSet);
            
            // final List<UserAction> detectedEvents = new ArrayList<>();
            currentDetector.addObserver((signature, match) -> {
                UserAction event = new UserAction(var, match.get(0).get(0).getTimestamp());
                PrintWriterUtils.println(event, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
                detectedEvents.add(event);
            });

            //-------difference with layer2 ( for line 273-283)
            if(isRangeBasedForCurrent){
                currentDetector.mClusterMatchers.forEach(cm -> cm.performDetectionRangeBased());
            }
            else{
                currentDetector.mClusterMatchers.forEach(cm -> cm.performDetectionConservative());
            }

            Detector.add(currentDetector);
        }

        final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM).
                withLocale(Locale.US).withZone(ZoneId.of("America/Los_Angeles"));

        // Outputs information about a detected event to std.out
        final Consumer<UserAction> outputter = ua -> {   //-------difference with layer2
            String eventDescription;
            int index=ua.getType();

            if(index<0 || index> n){
                throw new AssertionError("unhandled event type");
            }

            eventDescription=eventNames.get(index);
            // switch (ua.getType()) {
            //     case TOGGLE_ON:
            //         eventDescription = "ON";
            //         break;
            //     case TOGGLE_OFF:
            //         eventDescription = "OFF";
            //         break;
            //     default:
            //         throw new AssertionError("unhandled event type");
            // }
            // TODO: Uncomment the following if we want the old style print-out messages
            // String output = String.format("%s",
            // dateTimeFormatter.format(ua.getTimestamp()));
            // System.out.println(output);
            PrintWriterUtils.println(ua, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
        };

        // Let's create observers that construct a UserAction representing the detected event.
        // final List<UserAction> detectedEvents = new ArrayList<>();
        // onDetector.addObserver((searched, match) -> {
        //     PcapPacket firstPkt = match.get(0).get(0);
        //     UserAction event = new UserAction(UserAction.Type.TOGGLE_ON, firstPkt.getTimestamp());
        //     detectedEvents.add(event);
        // });
        // offDetector.addObserver((searched, match) -> {
        //     PcapPacket firstPkt = match.get(0).get(0);
        //     UserAction event = new UserAction(UserAction.Type.TOGGLE_OFF, firstPkt.getTimestamp());
        //     //PrintWriterUtils.println(event, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
        //     detectedEvents.add(event);
        // });

        PcapHandle handle;
        try {
            handle = Pcaps.openOffline(pcapFile, PcapHandle.TimestampPrecision.NANO);
        } catch (PcapNativeException pne) {
            handle = Pcaps.openOffline(pcapFile);
        }
        PcapHandleReader reader = new PcapHandleReader(handle, p -> true);
        for(int i=0;i<n;i++)
        {
            Layer3SignatureDetector curr = Detector.get(i);
            reader.addPacketListener(curr);
        }
        reader.readFromHandle();

        // // TODO: need a better way of triggering detection than this...
        // if (isRangeBasedForOn) {
        //     onDetector.mClusterMatchers.forEach(cm -> cm.performDetectionRangeBased());
        // } else {
        //     onDetector.mClusterMatchers.forEach(cm -> cm.performDetectionConservative());
        // }
        // if (isRangeBasedForOff) {
        //     offDetector.mClusterMatchers.forEach(cm -> cm.performDetectionRangeBased());
        // } else {
        //     offDetector.mClusterMatchers.forEach(cm -> cm.performDetectionConservative());
        // }

        // Sort the list of detected events by timestamp to make it easier to compare it line-by-line with the trigger
        // times file.
        Collections.sort(detectedEvents, Comparator.comparing(UserAction::getTimestamp));

        // Output the detected events
        detectedEvents.forEach(outputter);

        // String resultOn = "# Number of detected events of type " + UserAction.Type.TOGGLE_ON + ": " +
        //         detectedEvents.stream().filter(ua -> ua.getType() == UserAction.Type.TOGGLE_ON).count();
        // String resultOff = "# Number of detected events of type " + UserAction.Type.TOGGLE_OFF + ": " +
        //         detectedEvents.stream().filter(ua -> ua.getType() == UserAction.Type.TOGGLE_OFF).count();
        // PrintWriterUtils.println(resultOn, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
        // PrintWriterUtils.println(resultOff, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);

        for(int i=0;i<n;i++)   //-------difference with layer2
        {
            final int var=i;
            String resultCurrent = "# Number of detected events of type " + eventNames.get(i) + ": " +
                detectedEvents.stream().filter(ua -> ua.getType() == var).count();
            
            PrintWriterUtils.println(resultCurrent, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
            
        }  

        // Flush output to results file and close it.
        resultsWriter.flush();
        resultsWriter.close();
        // TODO: Temporary clean up until we clean the pipeline
//      List<UserAction> cleanedDetectedEvents = SignatureDetector.removeDuplicates(detectedEvents);
//      cleanedDetectedEvents.forEach(outputter);
    }

    /**
     * The signature that this {@link Layer3SignatureDetector} is searching for.
     */
    private final List<List<List<PcapPacket>>> mSignature;

    /**
     * The {@link Layer3ClusterMatcher}s in charge of detecting each individual sequence of packets that together make up the
     * the signature.
     */
    private final List<Layer3ClusterMatcher> mClusterMatchers;

    /**
     * For each {@code i} ({@code i >= 0 && i < pendingMatches.length}), {@code pendingMatches[i]} holds the matches
     * found by the {@link Layer3ClusterMatcher} at {@code mClusterMatchers.get(i)} that have yet to be "consumed", i.e.,
     * have yet to be included in a signature detected by this {@link Layer3SignatureDetector} (a signature can be encompassed
     * of multiple packet sequences occurring shortly after one another on multiple connections).
     */
    private final List<List<PcapPacket>>[] pendingMatches;

    /**
     * Maps a {@link Layer3ClusterMatcher} to its corresponding index in {@link #pendingMatches}.
     */
    private final Map<Layer3ClusterMatcher, Integer> mClusterMatcherIds;

    private final List<SignatureDetectionObserver> mObservers = new ArrayList<>();

    private int mInclusionTimeMillis;

    /**
     * Remove duplicates in {@code List} of {@code UserAction} objects. We need to clean this up for user actions
     * that appear multiple times.
     * TODO: This static method is probably just for temporary and we could get rid of this after we clean up
     * TODO:    the pipeline
     *
     * @param listUserAction A {@link List} of {@code UserAction}.
     *
     */
    public static List<UserAction> removeDuplicates(List<UserAction> listUserAction) {

        // Iterate and check for duplicates (check timestamps)
        Set<Long> epochSecondSet = new HashSet<>();
        // Create a target list for cleaned up list
        List<UserAction> listUserActionClean = new ArrayList<>();
        for(UserAction userAction : listUserAction) {
            // Don't insert if any duplicate is found
            if(!epochSecondSet.contains(userAction.getTimestamp().getEpochSecond())) {
                listUserActionClean.add(userAction);
                epochSecondSet.add(userAction.getTimestamp().getEpochSecond());
            }
        }
        return listUserActionClean;
    }

    public Layer3SignatureDetector(List<List<List<PcapPacket>>> searchedSignature, String routerWanIp,
                                   int inclusionTimeMillis, boolean isRangeBased, double eps,
                                   int delta, Set<Integer> packetSet) {
        // note: doesn't protect inner lists from changes :'(
        mSignature = Collections.unmodifiableList(searchedSignature);
        // Generate corresponding/appropriate ClusterMatchers based on the provided signature
        List<Layer3ClusterMatcher> clusterMatchers = new ArrayList<>();
        for (List<List<PcapPacket>> cluster : mSignature) {
            clusterMatchers.add(new Layer3ClusterMatcher(cluster, routerWanIp, inclusionTimeMillis,
                    isRangeBased, eps, delta, packetSet, this));
        }
        mClusterMatchers = Collections.unmodifiableList(clusterMatchers);

        // < exploratory >
        pendingMatches = new List[mClusterMatchers.size()];
        for (int i = 0; i < pendingMatches.length; i++) {
            pendingMatches[i] = new ArrayList<>();
        }
        Map<Layer3ClusterMatcher, Integer> clusterMatcherIds = new HashMap<>();
        for (int i = 0; i < mClusterMatchers.size(); i++) {
            clusterMatcherIds.put(mClusterMatchers.get(i), i);
        }
        mClusterMatcherIds = Collections.unmodifiableMap(clusterMatcherIds);
        mInclusionTimeMillis =
                inclusionTimeMillis == 0 ? TriggerTrafficExtractor.INCLUSION_WINDOW_MILLIS : inclusionTimeMillis;
    }

    public void addObserver(SignatureDetectionObserver observer) {
        mObservers.add(observer);
    }

    public boolean removeObserver(SignatureDetectionObserver observer) {
        return mObservers.remove(observer);
    }

    @Override
    public void gotPacket(PcapPacket packet) {
        // simply delegate packet reception to all ClusterMatchers.
        mClusterMatchers.forEach(cm -> cm.gotPacket(packet));
    }

    @Override
    public void onMatch(AbstractClusterMatcher clusterMatcher, List<PcapPacket> match) {
        // Add the match at the corresponding index
        pendingMatches[mClusterMatcherIds.get(clusterMatcher)].add(match);
        checkSignatureMatch();
    }

    private void checkSignatureMatch() {
        // << Graph-based approach using Balint's idea. >>
        // This implementation assumes that the packets in the inner lists (the sequences) are ordered by asc timestamp.

        // There cannot be a signature match until each Layer3ClusterMatcher has found a match of its respective sequence.
        if (Arrays.stream(pendingMatches).noneMatch(l -> l.isEmpty())) {
            // Construct the DAG
            final SimpleDirectedWeightedGraph<Vertex, DefaultWeightedEdge> graph =
                    new SimpleDirectedWeightedGraph<>(DefaultWeightedEdge.class);
            // Add a vertex for each match found by all ClusterMatchers
            // And maintain an array to keep track of what cluster matcher each vertex corresponds to
            final List<Vertex>[] vertices = new List[pendingMatches.length];
            for (int i = 0; i < pendingMatches.length; i++) {
                vertices[i] = new ArrayList<>();
                for (List<PcapPacket> sequence : pendingMatches[i]) {
                    Vertex v = new Vertex(sequence);
                    vertices[i].add(v); // retain reference for later when we are to add edges
                    graph.addVertex(v); // add to vertex to graph
                }
            }
            // Add dummy source and sink vertices to facilitate search.
            final Vertex source = new Vertex(null);
            final Vertex sink = new Vertex(null);
            graph.addVertex(source);
            graph.addVertex(sink);
            // The source is connected to all vertices that wrap the sequences detected by Layer3ClusterMatcher at index 0.
            // Note: zero cost edges as this is just a dummy link to facilitate search from a common start node.
            for (Vertex v : vertices[0]) {
                DefaultWeightedEdge edge = graph.addEdge(source, v);
                graph.setEdgeWeight(edge, 0.0);
            }
            // Similarly, all vertices that wrap the sequences detected by the last Layer3ClusterMatcher of the signature
            // are connected to the sink node.
            for (Vertex v : vertices[vertices.length-1]) {
                DefaultWeightedEdge edge = graph.addEdge(v, sink);
                graph.setEdgeWeight(edge, 0.0);
            }
            // Now link sequences detected by Layer3ClusterMatcher at index i to sequences detected by Layer3ClusterMatcher at index
            // i+1 if they obey the timestamp constraint (i.e., that the latter is later in time than the former).
            for (int i = 0; i < vertices.length; i++) {
                int j = i + 1;
                if (j < vertices.length) {
                    for (Vertex iv : vertices[i]) {
                        PcapPacket ivLast = iv.sequence.get(iv.sequence.size()-1);
                        for (Vertex jv : vertices[j]) {
                            PcapPacket jvFirst = jv.sequence.get(jv.sequence.size()-1);
                            if (ivLast.getTimestamp().isBefore(jvFirst.getTimestamp())) {
                                DefaultWeightedEdge edge = graph.addEdge(iv, jv);
                                // The weight is the duration of the i'th sequence plus the duration between the i'th
                                // and i+1'th sequence.
                                Duration d = Duration.
                                        between(iv.sequence.get(0).getTimestamp(), jvFirst.getTimestamp());
                                // Unfortunately weights are double values, so must convert from long to double.
                                // TODO: need nano second precision? If so, use d.toNanos().
                                // TODO: risk of overflow when converting from long to double..?
                                graph.setEdgeWeight(edge, Long.valueOf(d.toMillis()).doubleValue());
                            }
                            // Alternative version if we cannot assume that sequences are ordered by timestamp:
//                            if (iv.sequence.stream().max(Comparator.comparing(PcapPacket::getTimestamp)).get()
//                                    .getTimestamp().isBefore(jv.sequence.stream().min(
//                                            Comparator.comparing(PcapPacket::getTimestamp)).get().getTimestamp())) {
//
//                            }
                        }
                    }
                }
            }
            // Graph construction complete, run shortest-path to find a (potential) signature match.
            DijkstraShortestPath<Vertex, DefaultWeightedEdge> dijkstra = new DijkstraShortestPath<>(graph);
            GraphPath<Vertex, DefaultWeightedEdge> shortestPath = dijkstra.getPath(source, sink);
            if (shortestPath != null) {
                // The total weight is the duration between the first packet of the first sequence and the last packet
                // of the last sequence, so we simply have to compare the weight against the timeframe that we allow
                // the signature to span. For now we just use the inclusion window we defined for training purposes.
                // Note however, that we must convert back from double to long as the weight is stored as a double in
                // JGraphT's API.
                if (((long)shortestPath.getWeight()) < mInclusionTimeMillis) {
                    // There's a signature match!
                    // Extract the match from the vertices
                    List<List<PcapPacket>> signatureMatch = new ArrayList<>();
                    for(Vertex v : shortestPath.getVertexList()) {
                        if (v == source || v == sink) {
                            // Skip the dummy source and sink nodes.
                            continue;
                        }
                        signatureMatch.add(v.sequence);
                        // As there is a one-to-one correspondence between vertices[] and pendingMatches[], we know that
                        // the sequence we've "consumed" for index i of the matched signature is also at index i in
                        // pendingMatches. We must remove it from pendingMatches so that we don't use it to construct
                        // another signature match in a later call.
                        pendingMatches[signatureMatch.size()-1].remove(v.sequence);
                    }
                    // Declare success: notify observers
                    mObservers.forEach(obs -> obs.onSignatureDetected(mSignature,
                            Collections.unmodifiableList(signatureMatch)));
                }
            }
        }
    }

    /**
     * Used for registering for notifications of signatures detected by a {@link Layer3SignatureDetector}.
     */
    interface SignatureDetectionObserver {

        /**
         * Invoked when the {@link Layer3SignatureDetector} detects the presence of a signature in the traffic that it's
         * examining.
         * @param searchedSignature The signature that the {@link Layer3SignatureDetector} reporting the match is searching
         *                          for.
         * @param matchingTraffic The actual traffic trace that matches the searched signature.
         */
        void onSignatureDetected(List<List<List<PcapPacket>>> searchedSignature,
                                 List<List<PcapPacket>> matchingTraffic);
    }

    /**
     * Encapsulates a {@code List<PcapPacket>} so as to allow the list to be used as a vertex in a graph while avoiding
     * the expensive {@link AbstractList#equals(Object)} calls when adding vertices to the graph.
     * Using this wrapper makes the incurred {@code equals(Object)} calls delegate to {@link Object#equals(Object)}
     * instead of {@link AbstractList#equals(Object)}. The net effect is a faster implementation, but the graph will not
     * recognize two lists that contain the same items--from a value and not reference point of view--as the same
     * vertex. However, this is fine for our purposes -- in fact restricting it to reference equality seems more
     * appropriate.
     */
    private static class Vertex {
        private final List<PcapPacket> sequence;
        private Vertex(List<PcapPacket> wrappedSequence) {
            sequence = wrappedSequence;
        }
    }
}
