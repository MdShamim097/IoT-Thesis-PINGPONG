package edu.uci.iotproject.trafficreassembly.layer2;

/**
 * For observing a {@link Layer2FlowReassembler}.
 *
 * @author Janus Varmarken
 */
public interface Layer2FlowReassemblerObserver {

    /**
     * Invoked when when a {@link Layer2FlowReassembler} detects a new flow (i.e., when it encounters traffic between two
     * MAC addresses that has not previously communicated in the traffic trace).
     *
     * @param reassembler The {@link Layer2FlowReassembler} that detected the new flow.
     * @param newFlow The new flow.
     */
    void onNewFlow(Layer2FlowReassembler reassembler, Layer2Flow newFlow);

}
