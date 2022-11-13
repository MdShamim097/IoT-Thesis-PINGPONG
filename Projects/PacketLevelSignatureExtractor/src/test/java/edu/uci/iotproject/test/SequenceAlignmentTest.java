package edu.uci.iotproject.test;

import edu.uci.iotproject.comparison.seqalignment.AlignmentPricer;
import edu.uci.iotproject.comparison.seqalignment.SequenceAlignment;
import org.junit.Before;
import org.junit.Test;

import java.util.function.ToIntBiFunction;
import java.util.function.ToIntFunction;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests the implementation of {@link SequenceAlignment}.
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public class SequenceAlignmentTest {

    private char[] lowercaseVowels;
    private char[] lowercaseConsonants;

    private Character[] meanChars;
    private Character[] nameChars;

    /**
     * Cost function for the alignment of letters in the example execution of the sequence alignment algorithm in
     * Kleinberg's and Tardos' "Algorithm Design", where 'mean' and 'name' are aligned.
     */
    private ToIntBiFunction<Character, Character> kleinbergExampleAlignmentCostFunc;

    /**
     * Cost function for the alignment of letters with gaps in the example execution of the sequence alignment algorithm
     * in Kleinberg's and Tardos' "Algorithm Design", where 'mean' and 'name' are aligned. Gap cost is set to 2,
     * regardless of input character.
     */
    private ToIntFunction<Character> kleinbergExampleGapCostFunc;

    /**
     * Calculates the cost of aligning a letter with another letter or a letter with a gap according to the cost recipe
     * used in the example in Kleinberg & Tardos.
     */
    private AlignmentPricer<Character> kleinbergAlignmentPricer;

    /**
     * Executes the sequence alignment algorithm using the cost function defined in the example in Kleinberg & Tardos,
     * i.e., {@link #kleinbergAlignmentPricer}.
     */
    private SequenceAlignment<Character> kleinbergSequenceAligner;

    @Before
    public void initialize() {
        // We consider 'y' a vowel for the sake of simplicity.
        // Note: we assume an all lowercase string!
        lowercaseVowels = new char[] { 'a', 'e', 'i',  'o', 'u', 'y' };
        lowercaseConsonants = new char[] { 'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'q', 'r', 's',
                't', 'v', 'w', 'x', 'z' };
        kleinbergExampleAlignmentCostFunc = (c1, c2) -> {
            // Unbox to primitive type for the sake of brevity in the statements to follow.
            final char char1 = c1.charValue();
            final char char2 = c2.charValue();

            // If char1 and char2 are the same characters, the cost of aligning them is 0.
            if (char1 == char2) return 0;

            final boolean char1IsVowel = isVowel(char1);
            final boolean char1IsConsonant = isConsonant(char1);
            final boolean char2IsVowel = isVowel(char2);
            final boolean char2IsConsonant = isConsonant(char2);

            // Alignment cost is undefined for non alphabet characters.
            if (!char1IsVowel && !char1IsConsonant) fail("not an alphabet letter: " + char1);
            if (!char2IsVowel && !char2IsConsonant) fail("not an alphabet letter: " + char2);

            // If char1 and char2 are both vowels or both consonants, the cost is 1.
            if (char1IsVowel && char2IsVowel || char1IsConsonant && char2IsConsonant) return 1;

            // If one of char1 and char2 is a consonant, while the other is a vowel, the cost is 3.
            return 3;
        };
        // The cost of a gap is 2, regardless of what letter is aligned with the gap.
        kleinbergExampleGapCostFunc = c -> 2;

        // char[] -> Character[] conversion courtesy of https://stackoverflow.com/a/27690990/1214974
        meanChars = "mean".chars().mapToObj(c -> (char)c).toArray(Character[]::new);
        nameChars = "name".chars().mapToObj(c -> (char)c).toArray(Character[]::new);

        kleinbergAlignmentPricer = new AlignmentPricer<>(kleinbergExampleAlignmentCostFunc,
                kleinbergExampleGapCostFunc);

        kleinbergSequenceAligner = new SequenceAlignment<>(kleinbergAlignmentPricer);
    }

    @Test
    public void kleinbergExampleOptAlignmentCostShouldBe6() {
        // Cost of the optimal alignment of the two words
        final int optAlignmentCost = kleinbergSequenceAligner.calculateAlignment(meanChars, nameChars);
        final int expectedAlignmentCost = 6;
        String msg = String.format("Kleinberg example: computed opt != expected opt (computed=%d expected=%d)",
                optAlignmentCost, expectedAlignmentCost);
        assertTrue(msg, optAlignmentCost == expectedAlignmentCost);
    }


    @Test
    public void meanAlignedWithEmptyStringShouldBe8() {
        final int optAlignmentCost = kleinbergSequenceAligner.calculateAlignment(meanChars, new Character[0]);
        // 'mean' aligned with the empty string equals paying four gap costs, so total cost is: 4 * 2 = 8.
        final int expectedAlignmentCost = 8;
        String msg = String.format("'mean' aligned with empty string: computed opt != expected opt (computed=%d expected=%d)",
                optAlignmentCost, expectedAlignmentCost);
        assertTrue(msg, optAlignmentCost == expectedAlignmentCost);
    }

    @Test
    public void mAlignedWithNameShouldBe6() {
        /*
         * Note: this also uses the cost function specified in Kleinberg & Tardos.
         * Best alignment should be:
         * n a m e
         * _ _ m _
         * This should have a cost of 3 * gapCost = 6
         */
        final int optAlignmentCost = kleinbergSequenceAligner.calculateAlignment(new Character[] { 'm' }, nameChars);
        final int expectedAlignmentCost = 6;
        String msg = String.format("'m' aligned with 'name': computed opt != expected opt (computed=%d expected=%d)",
                optAlignmentCost, expectedAlignmentCost);
        assertTrue(msg, optAlignmentCost == expectedAlignmentCost);
    }

    @Test
    public void meAlignedWithNameShouldBe4() {
        /*
         * Note: this also uses the cost function specified in Kleinberg & Tardos.
         * Best alignment should be:
         * n a m e
         * _ _ m e
         * This should have a cost of 2 * gapCost = 4
         */
        final int optAlignmentCost = kleinbergSequenceAligner.calculateAlignment(new Character[] { 'm', 'e' }, nameChars);
        final int expectedAlignmentCost = 4;
        String msg = String.format("'me' aligned with 'name': computed opt != expected opt (computed=%d expected=%d)",
                optAlignmentCost, expectedAlignmentCost);
        assertTrue(msg, optAlignmentCost == expectedAlignmentCost);
        // Check that order of arguments doesn't matter
        final int optAlignmentCostReversed = kleinbergSequenceAligner.calculateAlignment(nameChars, new Character[] { 'm', 'e' });
        msg = "'me' aligned with 'name': different order of arguments unexpectedly produced different result";
        assertTrue(msg, optAlignmentCostReversed == optAlignmentCost && optAlignmentCostReversed == expectedAlignmentCost);
    }

    @Test
    public void ameAlignedWithNameShouldBe2() {
        /*
         * Note: this also uses the cost function specified in Kleinberg & Tardos.
         * Best alignment should be:
         * n a m e
         * _ a m e
         * This should have a cost of 1 * gapCost = 2
         */
        final int optAlignmentCost = kleinbergSequenceAligner.calculateAlignment(new Character[] { 'a', 'm', 'e' }, nameChars);
        final int expectedAlignmentCost = 2;
        String msg = String.format("'ame' aligned with 'name': computed opt != expected opt (computed=%d expected=%d)",
                optAlignmentCost, expectedAlignmentCost);
        assertTrue(msg, optAlignmentCost == expectedAlignmentCost);
    }

    @Test
    public void fameAlignedWithNameShouldBe1() {
        /*
         * Note: this also uses the cost function specified in Kleinberg & Tardos.
         * Best alignment should be:
         * n a m e
         * f a m e
         * This should have a cost of 1 * consonantMatchedWithConsonantCost = 1
         */
        final int optAlignmentCost = kleinbergSequenceAligner.calculateAlignment(new Character[] { 'f', 'a', 'm', 'e' },
                nameChars);
        final int expectedAlignmentCost = 1;
        String msg = String.format("'fame' aligned with 'name': computed opt != expected opt (computed=%d expected=%d)",
                optAlignmentCost, expectedAlignmentCost);
        assertTrue(msg, optAlignmentCost == expectedAlignmentCost);
    }

    @Test
    public void nameAlignedWithNameShouldBe0() {
        /*
         * Note: this also uses the cost function specified in Kleinberg & Tardos.
         * Best alignment should be:
         * n a m e
         * n a m e
         * This should have a cost of 0.
         */
        final int optAlignmentCost = kleinbergSequenceAligner.calculateAlignment(new Character[] { 'n', 'a', 'm', 'e' },
                nameChars);
        final int expectedAlignmentCost = 0;
        String msg = String.format("'name' aligned with 'name': computed opt != expected opt (computed=%d expected=%d)",
                optAlignmentCost, expectedAlignmentCost);
        assertTrue(msg, optAlignmentCost == expectedAlignmentCost);
    }

    @Test
    public void emanAlignedWithNameShouldBe6() {
        /*
         * Note: this also uses the cost function specified in Kleinberg & Tardos.
         * Best alignment should be:
         *
         * _ n a m e
         * e m a n _
         *
         *    or
         *
         * n a m e _
         * _ e m a n
         *
         * This should have a cost of 2 * gapCost + 2 * consonantMatchedWithConsonantCost = 2 * 2 + 2 * 1 = 6.
         */
        final int optAlignmentCost = kleinbergSequenceAligner.calculateAlignment(new Character[] { 'e', 'm', 'a', 'n' },
                nameChars);
        final int expectedAlignmentCost = 6;
        String msg = String.format("'eman' aligned with 'name': computed opt != expected opt (computed=%d expected=%d)",
                optAlignmentCost, expectedAlignmentCost);
        assertTrue(msg, optAlignmentCost == expectedAlignmentCost);
    }

    @Test
    public void naemAlignedWithNameShouldBe4() {
        /*
         * Note: this also uses the cost function specified in Kleinberg & Tardos.
         * Best alignment should be:
         *
         * n a _ m e
         * n a e m _
         *
         *    or
         *
         * n a m e _
         * n a _ e m
         *
         * This should have a cost of 2 * gapCost = 4.
         */
        final int optAlignmentCost = kleinbergSequenceAligner.calculateAlignment(new Character[] { 'n', 'a', 'e', 'm' },
                nameChars);
        final int expectedAlignmentCost = 4;
        String msg = String.format("'naem' aligned with 'name': computed opt != expected opt (computed=%d expected=%d)",
                optAlignmentCost, expectedAlignmentCost);
        assertTrue(msg, optAlignmentCost == expectedAlignmentCost);
    }


    /**
     * Checks if {@code letter} is a lowercase vowel. Note: for simplicity, 'y' is considered a <em>vowel</em>.
     * @param letter A {@code char} expected to be a vowel.
     * @return {@code true} if {@code letter} is a vowel, {@code false} otherwise.
     */
    private boolean isVowel(char letter) {
        for (char vowel : lowercaseVowels) {
            if (letter == vowel) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if {@code letter} is a lowercase consonant. Note: for simplicity, 'y' is considered a <em>vowel</em>.
     * @param letter A {@code char} expected to be a consonant.
     * @return {@code true} if {@code letter} is a consonant, {@code false} otherwise.
     */
    private boolean isConsonant(char letter) {
        for (char consonant : lowercaseConsonants) {
            if (letter == consonant) {
                return true;
            }
        }
        return false;
    }
}
