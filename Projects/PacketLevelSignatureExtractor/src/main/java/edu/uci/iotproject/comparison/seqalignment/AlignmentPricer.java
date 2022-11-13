package edu.uci.iotproject.comparison.seqalignment;

import java.util.function.ToIntBiFunction;
import java.util.function.ToIntFunction;

/**
 * Provides a generic implementation for the calculation of the cost of aligning two elements of a sequence as part of
 * the sequence alignment algorithm (the algorithm is implemented in {@link SequenceAlignment}).
 *
 * @param <T> The type of the elements that are being aligned.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class AlignmentPricer<T> {

    /**
     * A function that provides the cost of aligning a {@link T} with a gap.
     */
    private final ToIntFunction<T> mGapCostFunction;

    /**
     * A function that provides the cost of aligning a {@link T} with some other {@link T}.
     */
    private final ToIntBiFunction<T,T> mAlignmentCostFunction;

    /**
     * Constructs a new {@link AlignmentPricer}.
     *
     * @param alignmentCostFunction A function that specifies the cost of aligning a {@link T} with some other {@link T}
     *                              (e.g., based on the values of the properties of the two instances).
     * @param gapCostFunction A function that specifies the cost of aligning a {@link T} with a gap. Note that the
     *                        function is free to specify <em>different</em> gap costs for different {@link T}s.
     */
    public AlignmentPricer(ToIntBiFunction<T,T> alignmentCostFunction, ToIntFunction<T> gapCostFunction) {
        mAlignmentCostFunction = alignmentCostFunction;
        mGapCostFunction = gapCostFunction;
    }

    /**
     * Calculate the cost of aligning {@code item1} with {@code item2}. If either of the two arguments is set to
     * {@code null}, the cost of aligning the other argument with a gap will be returned. Note that both arguments
     * cannot be {@code null} at the same time as that translates to aligning a gap with a gap, which is pointless.
     *
     * @param item1 The first of the two aligned objects. Set to {@code null} to calculate the cost of aligning
     *              {@code item2} with a gap.
     * @param item2 The second of the two aligned objects. Set to {@code null} to calculate the cost of aligning
     *              {@code item2} with a gap.
     * @return The cost of aligning {@code item1} with {@code item2}.
     */
    public int alignmentCost(T item1, T item2) {
        // If both arguments are null, the caller is aligning a gap with a gap which is pointless might as well remove
        // both gaps in that case!)
        if (item1 == null && item2 == null) {
            throw new IllegalArgumentException("Both arguments cannot be null: you are aligning a gap with a gap!");
        }
        // If one item is null, it means we're aligning an int with a gap.
        // Invoke the provided gap cost function to get the gap cost.
        if (item1 == null) {
            return mGapCostFunction.applyAsInt(item2);
        }
        if (item2 == null) {
            return mGapCostFunction.applyAsInt(item1);
        }
        // If both arguments are present, we simply delegate the task of calculating the cost of aligning the two items
        // to the provided alignment cost function.
        return mAlignmentCostFunction.applyAsInt(item1, item2);
    }

}
