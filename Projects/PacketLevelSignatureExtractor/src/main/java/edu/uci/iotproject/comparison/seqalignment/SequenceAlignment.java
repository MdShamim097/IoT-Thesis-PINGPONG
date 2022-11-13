package edu.uci.iotproject.comparison.seqalignment;

/**
 * A generic implementation of the sequence alignment algorithm given in Kleinberg's and Tardos' "Algorithm Design".
 * This implementation is the basic version. There is a more complex version which significantly reduces the space
 * complexity at a slight cost to time complexity.
 *
 * @param <ALIGNMENT_UNIT> The <em>unit of the alignment</em>, or, in other words, the <em>granularity</em> of the
 *                        alignment. For example, for 'classical' string alignment (as in sequence alignment where we
 *                        try to align two strings character by character -- the example most often used in books on
 *                        algorithms) this would be a {@link Character}. As a second example, by specifying
 *                        {@link String}, one can decrease the granularity so as to align <em>blocks</em> of characters
 *                        (e.g., if one wants to align to two string arrays).
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class SequenceAlignment<ALIGNMENT_UNIT> {


    /**
     * Provides the cost of aligning two {@link ALIGNMENT_UNIT}s with one another as well as the cost of aligning an
     * {@link ALIGNMENT_UNIT} with a gap.
     */
    private final AlignmentPricer<ALIGNMENT_UNIT> mAlignmentPricer;

    /**
     * Constructs a new {@link SequenceAlignment}. The new instance relies on the provided {@code alignmentPricer} to
     * provide the cost of aligning two {@link ALIGNMENT_UNIT}s as well as the cost of aligning an
     * {@link ALIGNMENT_UNIT} with a gap.
     *
     * @param alignmentPricer An {@link AlignmentPricer} that provides the cost of aligning two {@link ALIGNMENT_UNIT}s
     *                        with one another as well as the cost of aligning an {@link ALIGNMENT_UNIT} with a gap.
     */
    public SequenceAlignment(AlignmentPricer<ALIGNMENT_UNIT> alignmentPricer) {
        mAlignmentPricer = alignmentPricer;
    }


    /**
     * Calculates the cost of aligning {@code sequence1} with {@code sequence2}.
     *
     * @param sequence1 A sequence that is to be aligned with {@code sequence2}.
     * @param sequence2 A sequence that is to be aligned with {@code sequence1}.
     *
     * @return The cost of aligning {@code sequence1} with {@code sequence2}.
     */
    public int calculateAlignment(ALIGNMENT_UNIT[] sequence1, ALIGNMENT_UNIT[] sequence2) {
        int[][] costs = new int[sequence1.length + 1][sequence2.length +1];
        /*
         * TODO:
         * This is a homebrewn initialization; it is different from the one in the Kleinberg book - is it correct?
         * It tries to add support for *different* gap costs depending on the input (e.g., such that one can say that
         * matching a 'c' with a gap is more expensive than matching a 'b' with a gap).
         */
        for (int i = 1; i <= sequence1.length; i++) {
            costs[i][0] = mAlignmentPricer.alignmentCost(sequence1[i-1], null) + costs[i-1][0];
        }
        for (int j = 1; j <= sequence2.length; j++) {
            costs[0][j] = mAlignmentPricer.alignmentCost(sequence2[j-1], null) + costs[0][j-1];
        }
        for (int j = 1; j <= sequence2.length; j++) {
            for (int i = 1; i <= sequence1.length; i++) {
                // The cost when current items of both sequences are aligned.
                int costAligned = mAlignmentPricer.alignmentCost(sequence2[j-1], sequence1[i-1]) + costs[i-1][j-1];
                // The cost when current item from sequence1 is not aligned (it's matched with a gap)
                int seq1ItemNotMached = mAlignmentPricer.alignmentCost(sequence1[i-1], null) + costs[i-1][j];
                // The cost when current item from sequence2 is not aligned (it's matched with a gap)
                int seq2ItemNotMached = mAlignmentPricer.alignmentCost(sequence2[j-1], null) + costs[i][j-1];
                costs[i][j] = Math.min(costAligned, Math.min(seq1ItemNotMached, seq2ItemNotMached));
            }
        }
        return costs[sequence1.length][sequence2.length];
    }
}
