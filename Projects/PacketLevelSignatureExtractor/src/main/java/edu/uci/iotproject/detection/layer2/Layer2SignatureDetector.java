package edu.uci.iotproject.detection.layer2;
import edu.uci.iotproject.filenaming.*;
import edu.uci.iotproject.analysis.TriggerTrafficExtractor;
import edu.uci.iotproject.analysis.UserAction;
import edu.uci.iotproject.detection.AbstractClusterMatcher;
import edu.uci.iotproject.detection.ClusterMatcherObserver;
import edu.uci.iotproject.detection.SignatureDetectorObserver;
import edu.uci.iotproject.io.PcapHandleReader;
import edu.uci.iotproject.io.PrintWriterUtils;
import edu.uci.iotproject.trafficreassembly.layer2.Layer2Flow;
import edu.uci.iotproject.trafficreassembly.layer2.Layer2FlowReassembler;
import edu.uci.iotproject.util.PcapPacketUtils;
import edu.uci.iotproject.util.PrintUtils;
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
import java.util.*;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Performs layer 2 signature detection.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class Layer2SignatureDetector implements PacketListener, ClusterMatcherObserver {

    /**
     * If set to {@code true}, output written to the results file is also dumped to standard out.
     */
    private static boolean DUPLICATE_OUTPUT_TO_STD_OUT = true;

    /**
     * Router's MAC.
     * This is only useful for the filter for direction when it is a WAN signature (Phone-Cloud or Device-Cloud).
     * Phone-Device signatures do not have router MAC address in it.
     */
    // TODO: We can remove the following constants if we do remove router's MAC filtering for directions
    private static String TRAINING_ROUTER_WLAN_MAC = null;
    private static String ROUTER_WLAN_MAC = null;
    //private static String TRAINING_ROUTER_WLAN_MAC = "b0:b9:8a:73:69:8e";
    //private static String ROUTER_WLAN_MAC = "00:c1:b1:14:eb:31";

    private static List<Function<Layer2Flow, Boolean>> parseSignatureMacFilters(String filtersString) {
        List<Function<Layer2Flow, Boolean>> filters = new ArrayList<>();
        String[] filterRegexes = filtersString.split(";");
        for (String filterRegex : filterRegexes) {
            final Pattern regex = Pattern.compile(filterRegex);
            // Create a filter that includes all flows where one of the two MAC addresses match the regex.
            filters.add(flow -> regex.matcher(flow.getEndpoint1().toString()).matches() || regex.matcher(flow.getEndpoint2().toString()).matches());
        }
        return filters;
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException, IOException {
        String errMsg = String.format("SPECTO version 1.0\n" +
                        "Copyright (C) 2018-2019 Janus Varmarken and Rahmadi Trimananda.\n" +
                        "University of California, Irvine.\n" +
                        "All rights reserved.\n\n" +
                        "Usage: %s inputPcapFile onAnalysisFile offAnalysisFile onSignatureFile offSignatureFile " +
                        "resultsFile signatureDuration eps onMaxSkippedPackets offMaxSkippedPackets" +
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
                Layer2SignatureDetector.class.getSimpleName());
        String optParamsExplained = "Above are the required, positional arguments. In addition to these, the " +
                "following options and associated positional arguments may be used:\n" +
                "  '-onmacfilters <regex>;<regex>;...;<regex>' which specifies that sequence matching should ONLY" +
                " be performed on flows where the MAC of one of the two endpoints matches the given regex. Note " +
                "that you MUST specify a regex for each cluster of the signature. This is to facilitate more " +
                "aggressive filtering on parts of the signature (e.g., the communication that involves the " +
                "smart home device itself as one can drop all flows that do not include an endpoint with a MAC " +
                "that matches the vendor's prefix).\n" +
                "  '-offmacfilters <regex>;<regex>;...;<regex>' works exactly the same as onmacfilters, but " +
                "applies to the OFF signature instead of the ON signature.\n" +
                "  '-sout <boolean literal>' true/false literal indicating if output should also be printed to std out; default is true.\n" +
                "  '-vpn <router mac>' router's MAC address; this is to simulate a VPN that combines all flows even when the traffic is not a VPN traffic.\n" +
                "  '-onskipped <max duration of on-signature>' the maximum duration of ON signature detection.\n" +
                "  '-offskipped <max duration of off-signature>' the maximum duration of OFF signature detection.\n";
        // Parse required parameters.
        if (args.length < 8) {
            System.out.println(errMsg);
            System.out.println(optParamsExplained);
            return;
        }
        final String pcapFile = args[0];
        final String ClusterAnalysisFile = args[1];
        final String SignatureFile = args[2];
        final String resultsFile = args[3];
        final int signatureDuration = Integer.parseInt(args[4]);
        final int signatureLength = Integer.parseInt(args[4]);
        final double eps = Double.parseDouble(args[5]);
        final String eventTypes = args[6];
        //final String eventsOccurred = args[7]; // ----------we have an unused argumment in [7]

        File eventTypesFile = new File(eventTypes);
        //File eventsOccurredFile = new File(eventsOccurred);

        // Additional feature---relaxed matching
        int delta = 0;
        final Set<Integer> packetSet = new HashSet<>();
        if (args.length > 8 && args[8].equals("-r")) {
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
        
        // Parse optional parameters.
        //List<Function<Layer2Flow, Boolean>> onSignatureMacFilters = null, offSignatureMacFilters = null;
        List<List<Function<Layer2Flow, Boolean>>> SignatureMacFilters = new ArrayList<>();
        for(int i=0;i<n;i++)
        {
            SignatureMacFilters.add(null);
        }

        String vpnClientMacAddress = null;
        // TODO: Currently the skipped packets implementation is not activated.
        // TODO: We looked into limiting the number of skipped packets to declare a signature match at layer-2.
        //int onMaxSkippedPackets = -1;
        //int offMaxSkippedPackets = -1;
        int [] MaxSkippedPackets = new int[n];
        for(int i=0;i<n;i++)
        {
            MaxSkippedPackets[i] = -1;
        }
        // final int optParamsStartIdx = 8;
        // if (args.length > optParamsStartIdx) {
        //     for (int i = optParamsStartIdx; i < args.length; i++) {
        //         if (args[i].equalsIgnoreCase("-onMacFilters")) {
        //             // Next argument is the cluster-wise MAC filters (separated by semicolons).
        //             onSignatureMacFilters = parseSignatureMacFilters(args[i+1]);
        //         } else if (args[i].equalsIgnoreCase("-offMacFilters")) {
        //             // Next argument is the cluster-wise MAC filters (separated by semicolons).
        //             offSignatureMacFilters = parseSignatureMacFilters(args[i+1]);
        //         } else if (args[i].equalsIgnoreCase("-sout")) {
        //             // Next argument is a boolean true/false literal.
        //             DUPLICATE_OUTPUT_TO_STD_OUT = Boolean.parseBoolean(args[i+1]);
        //         } else if (args[i].equalsIgnoreCase("-vpn")) {
        //             vpnClientMacAddress = args[i+1];
        //         } else if (args[i].equalsIgnoreCase("-onskipped")) {
        //             if (i+2 > args.length - 1 || !args[i+2].equalsIgnoreCase("-offskipped")) {
        //                 throw new Error("Please make sure that the -onskipped and -offskipped options are both used at the same time...");
        //             }
        //             if (args[i+2].equalsIgnoreCase("-offskipped")) {
        //                 onMaxSkippedPackets = Integer.parseInt(args[i+1]);
        //                 offMaxSkippedPackets = Integer.parseInt(args[i+3]);
        //             }
        //         }
        //     }
        // }

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

        // Create signature detectors and add observers that output their detected events.
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
        // Update the signature with ranges if it is range-based
        List<Layer2SignatureDetector> Detector = new ArrayList<>();
        final List<UserAction> detectedEvents = new ArrayList<>(); //---updated on 27/11/2022
        for(int i=0;i<n;i++)
        { 
            final int var=i;
            final String name=eventNames.get(i);
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
            List<Function<Layer2Flow, Boolean>> currentSignatureMacFilters = SignatureMacFilters.get(i);

            Layer2SignatureDetector currentDetector = currentSignatureMacFilters == null ?
                    new Layer2SignatureDetector(currentSignature, TRAINING_ROUTER_WLAN_MAC, ROUTER_WLAN_MAC, 
                            //signatureDuration,
                            signatureLength,
                            isRangeBasedForCurrent, eps, MaxSkippedPackets[i], vpnClientMacAddress, delta, packetSet) :
                    new Layer2SignatureDetector(currentSignature, TRAINING_ROUTER_WLAN_MAC, ROUTER_WLAN_MAC,
                            currentSignatureMacFilters,
                            //signatureDuration,
                            signatureLength, isRangeBasedForCurrent, eps, MaxSkippedPackets[i],
                            vpnClientMacAddress, delta, packetSet);
            
            // final List<UserAction> detectedEvents = new ArrayList<>();
           
            currentDetector.addObserver((signature, match) -> {
                UserAction event = new UserAction(var, name , match.get(0).get(0).getTimestamp()); //-------changed on 02/12/2022
                PrintWriterUtils.println(event, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
                detectedEvents.add(event);
            });
            
            Detector.add(currentDetector);
        }
        // if (isRangeBasedForOff) {
        //     offSignature = PcapPacketUtils.useRangeBasedMatching(offSignature, offClusterAnalysis);
        // }
        // Layer2SignatureDetector offDetector = offSignatureMacFilters == null ?
        //         new Layer2SignatureDetector(offSignature, TRAINING_ROUTER_WLAN_MAC, ROUTER_WLAN_MAC, signatureDuration,
        //                 isRangeBasedForOff, eps, offMaxSkippedPackets, vpnClientMacAddress, delta, packetSet) :
        //         new Layer2SignatureDetector(offSignature, TRAINING_ROUTER_WLAN_MAC, ROUTER_WLAN_MAC, offSignatureMacFilters,
        //                 signatureDuration, isRangeBasedForOff, eps, offMaxSkippedPackets, vpnClientMacAddress, delta, packetSet);
        // final List<UserAction> detectedEvents = new ArrayList<>();
        // offDetector.addObserver((signature, match) -> {
        //     UserAction event = new UserAction(UserAction.Type.TOGGLE_OFF, match.get(0).get(0).getTimestamp());
        //     PrintWriterUtils.println(event, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
        //     detectedEvents.add(event);
        // });

        // Load the PCAP file
        PcapHandle handle;
        try {
            handle = Pcaps.openOffline(pcapFile, PcapHandle.TimestampPrecision.NANO);
        } catch (PcapNativeException pne) {
            handle = Pcaps.openOffline(pcapFile);
        }
        PcapHandleReader reader = new PcapHandleReader(handle, p -> true);
        for(int i=0;i<n;i++)
        {
            Layer2SignatureDetector curr = Detector.get(i);
            reader.addPacketListener(curr);
        }
        // Parse the file
        reader.readFromHandle();

        // String resultOff = "# Number of detected events of type " + UserAction.Type.TOGGLE_OFF + ": " +
        //         detectedEvents.stream().filter(ua -> ua.getType() == UserAction.Type.TOGGLE_OFF).count();
        // String offMaximumSkippedPackets = "# Maximum number of skipped packets in OFF signature " +
        //         Integer.toString(offDetector.getMaxSkippedPackets());
        // PrintWriterUtils.println(resultOn, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
        // PrintWriterUtils.println(resultOff, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);

        for(int i=0;i<n;i++)
        {
            final int var=i;
            Layer2SignatureDetector currentDetector = Detector.get(i);
            String resultCurrent = "# Number of detected events of type " + eventNames.get(i) + ": " +
                detectedEvents.stream().filter(ua -> ua.getType() == var).count();
            String currentMaximumSkippedPackets = "# Maximum number of skipped packets in " + eventNames.get(i) + " signature " +
                Integer.toString(currentDetector.getMaxSkippedPackets());
            
            PrintWriterUtils.println(resultCurrent, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
            
            if(MaxSkippedPackets[i] != -1)
            {
                PrintWriterUtils.println(MaxSkippedPackets[i], resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
                for (Integer skippedPackets : currentDetector.getSkippedPackets()) {
                    PrintWriterUtils.println(skippedPackets, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
                } 
            }
        }
        // Perform the skipped packet analysis if needed
        // if (onMaxSkippedPackets != -1 && offMaxSkippedPackets != -1) {
        //     PrintWriterUtils.println(onMaximumSkippedPackets, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
        //     for (Integer skippedPackets : onDetector.getSkippedPackets()) {
        //         PrintWriterUtils.println(skippedPackets, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
        //     }
        //     PrintWriterUtils.println(offMaximumSkippedPackets, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
        //     for (Integer skippedPackets : offDetector.getSkippedPackets()) {
        //         PrintWriterUtils.println(skippedPackets, resultsWriter, DUPLICATE_OUTPUT_TO_STD_OUT);
        //     }
        // }
        // // Flush output to results file and close it.
        resultsWriter.flush();
        resultsWriter.close();
    }

    /**
     * The signature that this {@link Layer2SignatureDetector} is searching for.
     */
    private final List<List<List<PcapPacket>>> mSignature;

    /**
     * The {@link Layer2ClusterMatcher}s in charge of detecting each individual sequence of packets that together make
     * up the the signature.
     */
    private final List<Layer2ClusterMatcher> mClusterMatchers;

    /**
     * For each {@code i} ({@code i >= 0 && i < mPendingMatches.length}), {@code mPendingMatches[i]} holds the matches
     * found by the {@link Layer2ClusterMatcher} at {@code mClusterMatchers.get(i)} that have yet to be "consumed",
     * i.e., have yet to be included in a signature detected by this {@link Layer2SignatureDetector} (a signature can
     * be encompassed of multiple packet sequences occurring shortly after one another on multiple connections).
     */
    private final List<List<PcapPacket>>[] mPendingMatches;

    /**
     * Maps a {@link Layer2ClusterMatcher} to its corresponding index in {@link #mPendingMatches}.
     */
    private final Map<Layer2ClusterMatcher, Integer> mClusterMatcherIds;

    /**
     * In charge of reassembling layer 2 packet flows.
     */
    private Layer2FlowReassembler mFlowReassembler;

    private final List<SignatureDetectorObserver> mObservers = new ArrayList<>();

    private int mInclusionTimeMillis;
    private int mInclusionPackets; // updated on 12/11/2022
    /**
     * Skipped-packet analysis.
     */
    private int mMaxSkippedPackets;
    private List<Integer> mSkippedPackets;



    public Layer2SignatureDetector(List<List<List<PcapPacket>>> searchedSignature, String trainingRouterWlanMac,
                                   String routerWlanMac,
                                   //int signatureDuration,
                                   int signatureLength, 
                                   boolean isRangeBased, double eps,
                                   int limitSkippedPackets, String vpnClientMacAddress, int delta, Set<Integer> packetSet) {
        this(searchedSignature, trainingRouterWlanMac, routerWlanMac, null, 
            //signatureDuration,
                signatureLength,
                isRangeBased, eps, limitSkippedPackets, vpnClientMacAddress, delta, packetSet);
    }

    public Layer2SignatureDetector(List<List<List<PcapPacket>>> searchedSignature, String trainingRouterWlanMac,
                             String routerWlanMac, List<Function<Layer2Flow, Boolean>> flowFilters,           // updated on 12/11/2022
                                   //int inclusionTimeMillis,
                                   int inclusionPacketNumbers,
                                   boolean isRangeBased, double eps, int limitSkippedPackets, String vpnClientMacAddress, int delta, Set<Integer> packetSet) {
        if (flowFilters != null && flowFilters.size() != searchedSignature.size()) {
            throw new IllegalArgumentException("If flow filters are used, there must be a flow filter for each cluster " +
                    "of the signature.");
        }
        mSignature = Collections.unmodifiableList(searchedSignature);
        List<Layer2ClusterMatcher> clusterMatchers = new ArrayList<>();
        for (int i = 0; i < mSignature.size(); i++) {
            List<List<PcapPacket>> cluster = mSignature.get(i);
            Layer2ClusterMatcher clusterMatcher = flowFilters == null ?
                    new Layer2ClusterMatcher(cluster, trainingRouterWlanMac, routerWlanMac,
                            //inclusionTimeMillis,
                            inclusionPacketNumbers,
                            isRangeBased, eps, limitSkippedPackets, delta, packetSet) :
                    new Layer2ClusterMatcher(cluster, trainingRouterWlanMac, routerWlanMac, flowFilters.get(i),
                            //inclusionTimeMillis,
                            inclusionPacketNumbers,
                            isRangeBased, eps, limitSkippedPackets, delta, packetSet);
            clusterMatcher.addObserver(this);
            clusterMatchers.add(clusterMatcher);
        }
        mClusterMatchers = Collections.unmodifiableList(clusterMatchers);
        mPendingMatches = new List[mClusterMatchers.size()];
        for (int i = 0; i < mPendingMatches.length; i++) {
            mPendingMatches[i] = new ArrayList<>();
        }
        Map<Layer2ClusterMatcher, Integer> clusterMatcherIds = new HashMap<>();
        for (int i = 0; i < mClusterMatchers.size(); i++) {
            clusterMatcherIds.put(mClusterMatchers.get(i), i);
        }
        mClusterMatcherIds = Collections.unmodifiableMap(clusterMatcherIds);
        // Register all cluster matchers to receive a notification whenever a new flow is encountered.
        if (vpnClientMacAddress != null) {
            mFlowReassembler = new Layer2FlowReassembler(vpnClientMacAddress);
        } else {
            mFlowReassembler = new Layer2FlowReassembler();
        }
        mClusterMatchers.forEach(cm -> mFlowReassembler.addObserver(cm));
        /*
        mInclusionTimeMillis =
                inclusionTimeMillis == 0 ? TriggerTrafficExtractor.INCLUSION_WINDOW_MILLIS : inclusionTimeMillis;
        */
        mInclusionPackets =
                inclusionPacketNumbers == 0 ? TriggerTrafficExtractor.INCLUSION_NUMBER_OF_PACKETS : inclusionPacketNumbers;
        
        mMaxSkippedPackets = 0;
        mSkippedPackets = new ArrayList<>();
    }

    public int getMaxSkippedPackets() {
        return mMaxSkippedPackets;
    }

    public List<Integer> getSkippedPackets() {
        for (Layer2ClusterMatcher matcher : mClusterMatchers) {
            mSkippedPackets.addAll(matcher.getSkippedPackets());
        }
        return mSkippedPackets;
    }

    @Override
    public void gotPacket(PcapPacket packet) {
        // Forward packet processing to the flow reassembler that in turn notifies the cluster matchers as appropriate
        mFlowReassembler.gotPacket(packet);
    }

    @Override
    public void onMatch(AbstractClusterMatcher clusterMatcher, List<PcapPacket> match) {
        // TODO: a cluster matcher found a match
        if (clusterMatcher instanceof Layer2ClusterMatcher) {
            // Add the match at the corresponding index
            mPendingMatches[mClusterMatcherIds.get(clusterMatcher)].add(match);
            checkSignatureMatch();
            // Update maximum number of skipped packets
            if (mMaxSkippedPackets < ((Layer2ClusterMatcher) clusterMatcher).getMaxSkippedPackets()) {
                mMaxSkippedPackets = ((Layer2ClusterMatcher) clusterMatcher).getMaxSkippedPackets();
            }
        }
    }

    public void addObserver(SignatureDetectorObserver observer) {
        mObservers.add(observer);
    }

    public boolean removeObserver(SignatureDetectorObserver observer) {
        return mObservers.remove(observer);
    }


    @SuppressWarnings("Duplicates")
    private void checkSignatureMatch() {
        // << Graph-based approach using Balint's idea. >>
        // This implementation assumes that the packets in the inner lists (the sequences) are ordered by asc timestamp.

        // There cannot be a signature match until each Layer3ClusterMatcher has found a match of its respective sequence.
        if (Arrays.stream(mPendingMatches).noneMatch(l -> l.isEmpty())) {
            // Construct the DAG
            final SimpleDirectedWeightedGraph<Vertex, DefaultWeightedEdge> graph =
                    new SimpleDirectedWeightedGraph<>(DefaultWeightedEdge.class);
            // Add a vertex for each match found by all cluster matchers.
            // And maintain an array to keep track of what cluster matcher each vertex corresponds to
            final List<Vertex>[] vertices = new List[mPendingMatches.length];
            for (int i = 0; i < mPendingMatches.length; i++) {
                vertices[i] = new ArrayList<>();
                for (List<PcapPacket> sequence : mPendingMatches[i]) {
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
            // The source is connected to all vertices that wrap the sequences detected by cluster matcher at index 0.
            // Note: zero cost edges as this is just a dummy link to facilitate search from a common start node.
            for (Vertex v : vertices[0]) {
                DefaultWeightedEdge edge = graph.addEdge(source, v);
                // graph.setEdgeWeight(edge, 0.0);
                graph.setEdgeWeight(edge, 1.0);
            }
            // Similarly, all vertices that wrap the sequences detected by the last cluster matcher of the signature
            // are connected to the sink node.
            for (Vertex v : vertices[vertices.length-1]) {
                DefaultWeightedEdge edge = graph.addEdge(v, sink);
                graph.setEdgeWeight(edge, 0.0);
            }
            // Now link sequences detected by the cluster matcher at index i to sequences detected by the cluster
            // matcher at index i+1 if they obey the timestamp constraint (i.e., that the latter is later in time than
            // the former).
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
                                //graph.setEdgeWeight(edge, Long.valueOf(d.toMillis()).doubleValue());
                                graph.setEdgeWeight(edge, 1.0);
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
                if (((long)shortestPath.getWeight()) < mInclusionPackets) {
                //if (((long)shortestPath.getWeight()) < mInclusionTimeMillis) {
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
                        mPendingMatches[signatureMatch.size()-1].remove(v.sequence);
                    }
                    // Declare success: notify observers
                    mObservers.forEach(obs -> obs.onSignatureDetected(mSignature,
                            Collections.unmodifiableList(signatureMatch)));
                }
            }
        }
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
