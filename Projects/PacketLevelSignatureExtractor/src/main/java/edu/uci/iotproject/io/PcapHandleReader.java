package edu.uci.iotproject.io;

import edu.uci.iotproject.analysis.PcapPacketFilter;
import org.pcap4j.core.*;

import java.io.EOFException;
import java.util.concurrent.TimeoutException;

/**
 * Reads packets from a {@link PcapHandle} (online or offline) and delivers those packets that pass the test exercised
 * by the provided {@link PcapPacketFilter} onto the provided {@link PacketListener}s.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class PcapHandleReader {

    private final PcapPacketFilter mPacketFilter;
    private final PcapHandle mHandle;
    private List<PacketListener> mPacketListeners;
    private volatile boolean mTerminated = false;

    /**
     * Create a {@code PcapHandleReader}.
     * @param handle An <em>open</em> {@link PcapHandle} that packets will be read from.
     * @param packetFilter A {@link PcapPacketFilter} that dictates which of the packets read from {@code handle} should
     *                     be delivered to {@code packetListeners}. Note that while a value of {@code null} is not
     *                     permitted here, the caller can instead simply provide an implementation that always returns
     *                     {@code true} if they want to include all packets read from {@code handle}.
     * @param packetListeners One or more {@link PacketListener}s to which those packets read from {@code handle} that
     *                        pass through {@code packetFilter} are delivered.
     */
    public PcapHandleReader(PcapHandle handle, PcapPacketFilter packetFilter, PacketListener... packetListeners) {
        mHandle = handle;
        mPacketFilter = packetFilter;
        // mPacketListeners = packetListeners;
        for(PacketListener packetListener:packetListeners)
        {
            mPacketListeners.add(packetListener);
        }
    }

    public PcapHandleReader(PcapHandle handle, PcapPacketFilter packetFilter, List<PacketListener> packetListeners) {
        mHandle = handle;
        mPacketFilter = packetFilter;
        // mPacketListeners = packetListeners;
        for(PacketListener packetListener:packetListeners)
        {
            mPacketListeners.add(packetListener);
        }
    }
    /**
     * Start reading (and filtering) packets from the provided {@link PcapHandle}.
     * @throws PcapNativeException if an error occurs in the pcap native library.
     * @throws NotOpenException if the provided {@code PcapHandle} is not open.
     */
    public void readFromHandle() throws PcapNativeException, NotOpenException {
        int outOfOrderPackets = 0;
        try {
            PcapPacket prevPacket = null;
            PcapPacket packet = null;

            while (!mTerminated) {
                try {
                    packet = mHandle.getNextPacketEx();
                } catch (TimeoutException te) {
                    System.err.println("timeout occurred while reading from network interface");
                    // No need to check termination flag here. Can defer it to the loop condition as it is the next
                    // instruction anyway.
                    continue;
                }

                if (packet == null) {
                    System.err.println("null-packet read from handle");
                    continue;
                }

                if (prevPacket != null && packet.getTimestamp().isBefore(prevPacket.getTimestamp())) {
                    outOfOrderPackets++;
                    /*
                    // Fail early if assumption doesn't hold.
                    mHandle.close();
                    throw new AssertionError("Packets not in ascending temporal order");
                    */
                }
                if (mPacketFilter.shouldIncludePacket(packet)) {
                    // Packet accepted for inclusion; deliver it to observing client code.
                    for (PacketListener consumer : mPacketListeners) {
                        consumer.gotPacket(packet);
                    }
                }
                prevPacket = packet;
            }
        } catch (EOFException eof) {
            // Reached end of file. All good.
            System.out.println(String.format("%s: finished reading pcap file", getClass().getSimpleName()));
        }
        if (outOfOrderPackets > 0) {
            System.err.println(
                    String.format("[[[ %s: %d packets appeared out of order (with regards to their timestamps) ]]]",
                            getClass().getSimpleName(), outOfOrderPackets));
        }
        mHandle.close();
    }

    /**
     * Stop reading from the wrapped {@link PcapHandle}. Note that this call only <em>initiates</em> the shutdown by
     * setting a termination flag. Shutdown will be deferred until the time at which this flag can be checked by
     * {@link #readFromHandle()}. For example, if {@link #readFromHandle()} is currently in the middle of a blocking
     * call to {@link PcapHandle#getNextPacketEx()}, shutdown will not occur until the next packet is returned from the
     * wrapped {@link PcapHandle} or its read timeout expires. Use {@link #hasTerminated()} to check if the shutdown
     * has completed.
     */
    public void stopReading() {
        mTerminated = true;
    }

    /**
     * Checks if this {@link PcapHandleReader} has gracefully terminated, i.e., that the wrapped {@link PcapHandle} has
     * been closed.
     *
     * @return {@code true} if this {@link PcapHandleReader} has terminated, {@code false} otherwise.
     */
    public boolean hasTerminated() {
        return mTerminated && !mHandle.isOpen();
    }

}
