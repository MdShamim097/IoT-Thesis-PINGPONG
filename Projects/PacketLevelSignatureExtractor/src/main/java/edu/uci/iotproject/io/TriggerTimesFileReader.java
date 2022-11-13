package edu.uci.iotproject.io;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Parses a file to obtain the timestamps at which the smart plug was toggled on/off.
 *
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 */
public class TriggerTimesFileReader {

    public static final ZoneId ZONE_ID_LOS_ANGELES = ZoneId.of("America/Los_Angeles");
    public static final ZoneId ZONE_ID_BUDAPEST = ZoneId.of("Europe/Budapest");

    /**
     * Reads a file with trigger timestamps and parses the timestamps into {@link Instant}s using the rules specified
     * by {@link #parseTriggerTimestamp(String, boolean)}.
     * @param fileName The absolute path to the file with trigger timestamps.
     * @param _24hFormat {@code true} if the timestamps in the file are in 24 hour format, {@code false} if they are in
     *                               AM/PM format.
     * @return A containing the trigger timestamps represented as {@code Instant}s.
     */
    public List<Instant> readTriggerTimes(String fileName, boolean _24hFormat) {
        List<Instant> listTriggerTimes = new ArrayList<>();
        File file = new File(fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String s;
            while ((s = br.readLine()) != null) {
                listTriggerTimes.add(parseTriggerTimestamp(s, _24hFormat));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("List has: " + listTriggerTimes.size());
        return listTriggerTimes;
    }

    /**
     * Parses a timestamp string to an {@link Instant} (UTC). Assumes timestamps are LA time.
     * Format is expected to be either "MM/dd/uuuu HH:mm:ss" or "MM/dd/uuuu h:mm:ss a".
     *
     * @param timestampStr The string containing a date-time timestamp for LA's timezone.
     * @param _24hFormat {@code true} if the time in {@code timestampStr} is given in 24 hour format, {@code false} if
     *                               it is given in AM/PM format.
     * @return An {@code Instant} representation of the parsed timestamp. Note that the {@code Instant} marks a point on
     *         the timeline in UTC. Use {@link Instant#atZone(ZoneId)} to convert to the corresponding time in a given
     *         timezone.
     */
    public Instant parseTriggerTimestamp(String timestampStr, boolean _24hFormat) {
        // Note: only one 'h' when not prefixed with leading 0 for 1-9; and only one 'a' for AM/PM marker in Java 8 time
        String format = _24hFormat ? "MM/dd/uuuu HH:mm:ss" : "MM/dd/uuuu h:mm:ss a";
        LocalDateTime localDateTime = LocalDateTime.parse(timestampStr, DateTimeFormatter.ofPattern(format, Locale.US));
        ZonedDateTime laZonedDateTime = localDateTime.atZone(ZONE_ID_LOS_ANGELES);
        return laZonedDateTime.toInstant();
    }

}
