package edu.uci.iotproject.analysis;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Set;

/**
 * Models a user's action, such as toggling the smart plug on/off at a given time.
 *
 * @author Janus Varmarken
 */
public class UserAction {

    private static volatile DateTimeFormatter TIMESTAMP_FORMATTER = DateTimeFormatter.ISO_ZONED_DATE_TIME.
            withZone(ZoneId.of("America/Los_Angeles"));

    private String mName;
    private Set<String> occurrences
    /**
     * Sets the {@link DateTimeFormatter} used when outputting a user action as a string and parsing a user action from
     * a string.
     * @param formatter The formatter to use for outputting and parsing.
     */
    public static void setTimestampFormatter(DateTimeFormatter formatter) {
        TIMESTAMP_FORMATTER = formatter;
    }

    /**
     * Instantiates a {@code UserAction} from a string that obeys the format used in {@link UserAction#toString()}.
     * @param string The string that represents a {@code UserAction}
     * @return A {@code UserAction} resulting from deserializing the string.
     */
    public static UserAction fromString(String string) {
        String[] parts = string.split("@");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid string format");
        }
        // If any of these two parses fail, an exception is thrown -- no need to check return values.
        //UserAction.Type actionType = UserAction.Type.valueOf(parts[0].trim());
        
        Instant timestamp = TIMESTAMP_FORMATTER.parse(parts[1].trim(), Instant::from);
        return new UserAction(0, timestamp);
    }


    /**
     * The specific type of action the user performed.
     */
    private final int mType;

    /**
     * The time the action took place.
     */
    private final Instant mTimestamp;

    public UserAction(int typeOfAction, Instant timeOfAction) {
        mType = typeOfAction;
        mTimestamp = timeOfAction;
        occurrences = new HashSet<String>();
    }

    public UserAction(int typeOfAction, String typeName , Instant timeOfAction) {
        mType = typeOfAction;
        mTimestamp = timeOfAction;
        mName=typeName;
        occurrences = new HashSet<String>();
    }

    public void setName(String typeName){
        mName=typeName;
    }

    public String getName(){
        return mName;
    }

    /**
     * Get the specific type of action performed by the user.
     * @return the specific type of action performed by the user.
     */
    public int getType() {
        return mType;
    }

    /**
     * Get the time at which the user performed this action.
     * @return the time at which the user performed this action.
     */
    public Instant getTimestamp() {
        return mTimestamp;
    }

    /**
     * Enum for indicating what type of action the user performed.
     */
    /*public enum Type {
        TOGGLE_ON, TOGGLE_OFF
    }*/


    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof UserAction) {
            UserAction that = (UserAction) obj;
            return this.mType == that.mType && this.mTimestamp.equals(that.mTimestamp);
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 17;
        String str=Integer.toString(mType); //-------changed on 26/11/2022
        hashCode = prime * hashCode + str.hashCode();
        hashCode = prime * hashCode + mTimestamp.hashCode();
        return hashCode;
    }

    @Override
    public String toString() {
        String ss = TIMESTAMP_FORMATTER.format(mTimestamp);
        if(occurrences.add(ss))
        {
            ss = ss+"# Unique";
        }
        else
        {
            ss = ss+"# Duplicate";
        }
       return String.format("%s @ %s", mName, ss); //-------changed on 02/12/2022
    }
}
