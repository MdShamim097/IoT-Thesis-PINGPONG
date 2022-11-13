package edu.uci.iotproject.io;

import org.pcap4j.core.*;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.util.Objects;

/**
 * Utility methods for setting up a {@link PcapHandleReader} that reads live traffic from a network interface card.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class LiveCapture {

    // This main method is just for experimental purposes!
    public static void main(String[] args) throws PcapNativeException, NotOpenException, InterruptedException {
        // ================================================ EXAMPLE USE ================================================
        final String outputPcapFile = System.getProperty("user.home") + "/temp/livecapture42.pcap";
        final PcapDumper outputter = Pcaps.openDead(DataLinkType.EN10MB, 65536).dumpOpen(outputPcapFile);
        // Prompt user to select what interface we should be listening to; dump packets to a file.
        PcapHandleReader reader = fromCliNicSelection(
                p -> {
                    try {
                        outputter.dump(p);
                    } catch (NotOpenException noe) {
                        noe.printStackTrace();
                    }
                }
        );

        // Read on separate thread so that we can get a chance to terminate the reader on this thread.
        Thread readerThread = new Thread(() -> {
            try {
                reader.readFromHandle();
            } catch (PcapNativeException e) {
                e.printStackTrace();
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
        });
        readerThread.start();

        // Pause to let reader read some packets before we terminate it.
        Thread.sleep(30_000);

        // Shutdown reader.
        reader.stopReading();
        System.out.println("Waiting for " + reader.getClass().getSimpleName() + " to terminate...");
        while (!reader.hasTerminated());
        // remember to flush any buffered output
        outputter.flush();
        System.out.println(reader.getClass().getSimpleName() + " terminated.");
        // =============================================================================================================
    }

    /**
     * Prompts the user to pick a Network Interface Card (NIC) for which live traffic is to be captured, then creates a
     * {@link PcapHandleReader} that is ready to start capturing live traffic from that NIC.
     *
     * @param listeners One or more {@link PacketListener}s to which packets read from the NIC will be delivered.
     *
     * @return A {@link PcapHandleReader} that is ready to start capturing live traffic from the selected NIC or
     *         {@code null} if no NICs can be found.
     *
     * @throws PcapNativeException if an error occurs in the pcap native library.
     */
    public static PcapHandleReader fromCliNicSelection(PacketListener... listeners) throws PcapNativeException {
        PcapNetworkInterface networkInterface = null;
        try {
            networkInterface = new NifSelector().selectNetworkInterface();
        } catch (IOException ioe) {
            System.err.println("No network interfaces found.");
            ioe.printStackTrace();
        }
        return networkInterface != null ? fromNic(networkInterface, listeners) : null;
    }

    /**
     * Creates a {@link PcapHandleReader} that is ready to start capturing live traffic from the provided Network
     * Interface Card (NIC).
     *
     * @param networkInterface The target NIC.
     * @param listeners One or more {@link PacketListener}s to which packets read from the NIC will be delivered.
     *
     * @return A {@link PcapHandleReader} that is ready to start capturing live traffic from the provided NIC.
     *
     * @throws PcapNativeException if an error occurs in the pcap native library.
     */
    public static PcapHandleReader fromNic(PcapNetworkInterface networkInterface, PacketListener... listeners)
            throws PcapNativeException {
        Objects.requireNonNull(networkInterface);
        int snapshotLength = 65536; // in bytes
        int readTimeout = 10000; // 0 is infinite on all systems but Solaris
        PcapHandle handle = networkInterface.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);
        // Supply a filter that accepts all packets (p -> true) as we want to examine all traffic.
        return new PcapHandleReader(handle, p -> true, listeners);
    }

}
