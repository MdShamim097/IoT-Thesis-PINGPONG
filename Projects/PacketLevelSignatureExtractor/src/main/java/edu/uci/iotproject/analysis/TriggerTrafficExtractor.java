package edu.uci.iotproject.analysis;

import edu.uci.iotproject.io.PcapHandleReader;
import org.pcap4j.core.*;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeoutException;

/**
 * TODO add class documentation.
 *
 * @author Janus Varmarken
 */
public class TriggerTrafficExtractor implements PcapPacketFilter {

    private final String mPcapFilePath;
    private final List<Instant> mTriggerTimes;
    private final String mDeviceIp;

    private int mTriggerIndex = 0;
    /**
     * The total number of packets marked for inclusion during one run of {@link #performExtraction(PacketListener...)}.
     */
    private long mIncludedPackets = 0;

    private int packetNumbers[];
    private int triggerCount=0;

    public static final int INCLUSION_WINDOW_MILLIS = 15_000;
    public static final int INCLUSION_NUMBER_OF_PACKETS = 27; 
    // TODO: Relax the inclusion time if needed
    //public static final int INCLUSION_WINDOW_MILLIS = 30_000;

    public TriggerTrafficExtractor(String pcapFilePath, List<Instant> triggerTimes, String deviceIp) throws PcapNativeException, NotOpenException {
        mPcapFilePath = pcapFilePath;
        
        triggerCount=triggerTimes.size();
        packetNumbers=new int[triggerCount];
        
        // Ensure that trigger times are sorted in ascending as we rely on this fact in the logic that works out if a
        // packet is related to a trigger.
        Collections.sort(triggerTimes, (i1, i2) -> {
            if (i1.isBefore(i2)) return -1;
            else if (i2.isBefore(i1)) return 1;
            else return 0;
        });
        mTriggerTimes = Collections.unmodifiableList(triggerTimes);
        mDeviceIp = deviceIp;
    }


    public void performExtraction(PacketListener... extractedPacketsConsumers) throws PcapNativeException, NotOpenException, TimeoutException {
        // Reset trigger index and packet counter in case client code chooses to rerun the extraction.
        mTriggerIndex = 0;
        mIncludedPackets = 0;
        PcapHandle handle;
        try {
            handle = Pcaps.openOffline(mPcapFilePath, PcapHandle.TimestampPrecision.NANO);
        } catch (PcapNativeException pne) {
            handle = Pcaps.openOffline(mPcapFilePath);
        }
        // Use the native support for BPF to immediately filter irrelevant traffic.
        handle.setFilter("ip host " + mDeviceIp, BpfProgram.BpfCompileMode.OPTIMIZE);
        PcapHandleReader pcapReader = new PcapHandleReader(handle, this, extractedPacketsConsumers);
        //System.out.println("Perform Extraction started");
        pcapReader.readFromHandle(); 
        //System.out.println("Perform Extraction finished");
    }

    /**
     * Return the number of extracted packets (i.e., packets selected for inclusion) as a result of the most recent call
     * to {@link #performExtraction(PacketListener...)}.
     *
     * @return the number of extracted packets (i.e., packets selected for inclusion) as a result of the most recent
     *         call to {@link #performExtraction(PacketListener...)}.
     */
    public long getPacketsIncludedCount() {
        return mIncludedPackets;
    }

    @Override
    public boolean shouldIncludePacket(PcapPacket packet) {
        // New version. Simpler, but slower: the later a packet arrives, the more elements of mTriggerTimes will need to
        // be traversed.
        // boolean include = mTriggerTimes.stream().anyMatch(
                
        //         trigger -> trigger.isBefore(packet.getTimestamp()) &&  
        //                 packet.getTimestamp().isBefore(trigger.plusMillis(INCLUSION_WINDOW_MILLIS))
                
        // );

        //System.out.println("Entered in shouldIncludePacket");
        boolean include=false;
        int index=-1;
        //System.out.println("Continue crossed, packet numbers "+ packetNumbers[0]+packetNumbers[1]+packetNumbers[2]);
        for(int i=0;i<triggerCount;i++){
            Instant trigger=mTriggerTimes.get(i);
            //System.out.println("Time is "+trigger+" Size"+mTriggerTimes.size());
            //System.out.println("Entered in "+i);
            if(!trigger.isBefore(packet.getTimestamp())) break;
            index=i;
        }
        //System.out.println("Index value "+index);
        if (index==-1){
            return include;
        }
        else{
            include=packetNumbers[index]<INCLUSION_NUMBER_OF_PACKETS;
            if(include){
                packetNumbers[index]++;
            }
        }

        if (include) {
            mIncludedPackets++;
            //System.out.println("Number = "+mIncludedPackets);
        }
        return include;

        /*
        // Old version. Faster, but more complex - is it correct?
        if (mTriggerIndex >= mTriggerTimes.size()) {
            // Don't include packet if we've exhausted the list of trigger times.
            return false;
        }

        // TODO hmm, is this correct?
        Instant trigger = mTriggerTimes.get(mTriggerIndex);
        if (trigger.isBefore(packet.getTimestamp()) &&
                packet.getTimestamp().isBefore(trigger.plusMillis(INCLUSION_WINDOW_MILLIS))) {
            // Packet lies within INCLUSION_WINDOW_MILLIS after currently considered trigger, include it.
            return true;
        } else {
            if (!trigger.isBefore(packet.getTimestamp())) {
                // Packet is before currently considered trigger, so it shouldn't be included
                return false;
            } else {
                // Packet is >= INCLUSION_WINDOW_MILLIS after currently considered trigger.
                // Proceed to next trigger to see if it lies in range of that.
                // Note that there's an assumption here that no two trigger intervals don't overlap!
                mTriggerIndex++;
                return shouldIncludePacket(packet);
            }
        }
        */
    }

}
