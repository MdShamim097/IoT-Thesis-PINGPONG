package edu.uci.iotproject.comparison.seqalignment;

/**
 * A sample {@link AlignmentPricer} for computing the cost of aligning integer values. In this sample implementation,
 * the cost of aligning two integers {@code i1} and {@code i2} is {@code Math.abs(i1 - i2)}, i.e., it is the absolute
 * value of the difference between {@code i1} and {@code i2}. The cost of aligning an integer {@code i} with a gap is
 * simply {@code i}, i.e., the gap is essentially treated as a zero.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class SampleIntegerAlignmentPricer extends AlignmentPricer<Integer> {

    /**
     * Constructs a new {@link SampleIntegerAlignmentPricer}.
     */
    public SampleIntegerAlignmentPricer() {
        // Cost of aligning integers i1 and i2 is the absolute value of their difference.
        // Cost of aligning integer i with a gap is i (as it was aligned with 0).
        super((i1,i2) -> Math.abs(i1 - i2) , (i) -> i);
    }

}
