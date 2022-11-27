package edu.uci.iotproject.evaluation;

import edu.uci.iotproject.analysis.TriggerTrafficExtractor;
import edu.uci.iotproject.analysis.UserAction;
import edu.uci.iotproject.io.PrintWriterUtils;
import edu.uci.iotproject.io.TriggerTimesFileReader;

import java.io.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Utility for comparing detected events to logged (actual) events.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class DetectionResultsAnalyzer {

    private static boolean DUPLICATE_OUTPUT_TO_STD_OUT = true;
    private static boolean DETECTED_EVENT_EXACT_MATCH;

    public static void main(String[] args) throws IOException {
        if (args.length < 4) {
            String errMsg = String.format("Usage: %s triggerTimesFile detectionOutputFile [stdOut]" +
                            "\n - triggerTimesFile: the file that contains the timestamps for the user actions" +
                            "\n - detectionOutputFile: the file that contains the detected events" +
                            "\n - analysisResultsFile: where to write the results of the detection analysis" +
                            "\n - matchEventType: true/false literal indicating if a detected event should" +
                                " have a matching type" +
                            "\n - stdOut: optional true/false literal indicating if output should also be printed to" +
                                " std out; default is true",
                    DetectionResultsAnalyzer.class.getSimpleName());
            System.out.println(errMsg);
            return;
        }
        String triggerTimesFile = args[0];
        File detectionOutputFile = new File(args[1]);
        String analysisResultsFile = args[2];
        DETECTED_EVENT_EXACT_MATCH = Boolean.parseBoolean(args[3]);
        if (args.length > 4) {
            DUPLICATE_OUTPUT_TO_STD_OUT = Boolean.parseBoolean(args[4]);
        }

        // -------------------------------------- Parse the input files --------------------------------------

        // Read the trigger times.
        // The trigger times file does not contain event types as we initially assumed that we would just be alternating
        // between ON and OFF.
        List<Instant> triggerTimestamps = new TriggerTimesFileReader().readTriggerTimes(triggerTimesFile, false);
        // Now generate user actions based on this alternating ON/OFF pattern.
        List<UserAction> triggers = new ArrayList<>();
        for (int i = 0; i < triggerTimestamps.size(); i++) {
            // NOTE: assumes triggers alternate between ON and OFF
            //UserAction.Type actionType = i % 2 == 0 ? UserAction.Type.TOGGLE_ON : UserAction.Type.TOGGLE_OFF;
            //triggers.add(new UserAction(actionType, triggerTimestamps.get(i))); 
            triggers.add(new UserAction(i, triggerTimestamps.get(i)));       //-------updated on 27/11/2022
        }
        // Read the detection output file, assuming a format as specified in UserAction.toString()
        List<UserAction> detectedEvents = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(detectionOutputFile))) {
            String s;
            while ((s = br.readLine()) != null) {
                if (s.startsWith("#")) {
                    // Ignore comments.
                    continue;
                }
                detectedEvents.add(UserAction.fromString(s));
            }
        }

        // -----------------  Now ready to compare the detected events with the logged events -----------------

        // To contain all detected events that could be mapped to a trigger
        List<UserAction> truePositives = new ArrayList<>();
        if (DETECTED_EVENT_EXACT_MATCH) {
            for (UserAction detectedEvent : detectedEvents) {
                Optional<UserAction> matchingTrigger = triggers.stream()
                        .filter(t -> t.getType() == detectedEvent.getType() &&
                                t.getTimestamp().isBefore(detectedEvent.getTimestamp()) &&
                                t.getTimestamp().plusMillis(TriggerTrafficExtractor.INCLUSION_WINDOW_MILLIS).
                                        isAfter(detectedEvent.getTimestamp())
                        ).findFirst();
                matchingTrigger.ifPresent(mt -> {
                    // We've consumed the trigger (matched it with a detected event), so remove it so we don't match with
                    // another detected event.
                    triggers.remove(mt);
                    // The current detected event was a true positive as we could match it with a trigger.
                    truePositives.add(detectedEvent);
                });
            }
            // TODO: Experimental
        } else { // DETECTED_EVENT_EXACT_MATCH == false
            for (UserAction detectedEvent : detectedEvents) {
                Optional<UserAction> matchingTrigger = triggers.stream()
                        .filter(t ->
                                t.getTimestamp().isBefore(detectedEvent.getTimestamp()) &&
                                t.getTimestamp().plusMillis(TriggerTrafficExtractor.INCLUSION_WINDOW_MILLIS).
                                        isAfter(detectedEvent.getTimestamp())
                        ).findFirst();
                matchingTrigger.ifPresent(mt -> {
                    // We've consumed the trigger (matched it with a detected event), so remove it so we don't match with
                    // another detected event.
                    triggers.remove(mt);
                    // The current detected event was a true positive as we could match it with a trigger.
                    truePositives.add(detectedEvent);
                });
            }
        }
        // Now the false positives are those elements in detectedEvents that are not in truePositives
        List<UserAction> falsePositives = new ArrayList<>();
        falsePositives.addAll(detectedEvents);
        falsePositives.removeAll(truePositives);

        // Output the results...
        PrintWriter outputter = new PrintWriter(new FileWriter(analysisResultsFile));
        PrintWriterUtils.println("---------- False negatives (events that were not detected) ----------", outputter, DUPLICATE_OUTPUT_TO_STD_OUT);
        for (UserAction missing : triggers) {
            PrintWriterUtils.println(missing, outputter, DUPLICATE_OUTPUT_TO_STD_OUT);
        }
        PrintWriterUtils.println("Total of " + Integer.toString(triggers.size()), outputter, DUPLICATE_OUTPUT_TO_STD_OUT);
        PrintWriterUtils.printEmptyLine(outputter, DUPLICATE_OUTPUT_TO_STD_OUT);
        PrintWriterUtils.println("---------- False positives (detected, but no matching trigger) ----------", outputter, DUPLICATE_OUTPUT_TO_STD_OUT);
        for (UserAction fp : falsePositives) {
            PrintWriterUtils.println(fp, outputter, DUPLICATE_OUTPUT_TO_STD_OUT);
        }
        PrintWriterUtils.println("Total of " + Integer.toString(falsePositives.size()), outputter, DUPLICATE_OUTPUT_TO_STD_OUT);
        outputter.flush();
        outputter.close();
    }

}
