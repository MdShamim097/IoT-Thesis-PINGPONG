package edu.uci.iotproject.io;

import java.io.PrintWriter;

/**
 * Utility methods for (jointly) printing to a {@link PrintWriter} (and standard output).
 *
 * @author Janus Varmarken {@literal <jvarmark@uci.edu>}
 * @author Rahmadi Trimananda {@literal <rtrimana@uci.edu>}
 */
public final class PrintWriterUtils {

    private PrintWriterUtils() {
        // Disallow instantiation. Static-only class.
    }

    /**
     * Invoke {@link PrintWriter#println(Object)} passing {@code line} as argument while also printing {@code line} to
     * standard output if {@code duplicateToStdOut} is {@code true}.
     * @param line The line to be printed.
     * @param writer The {@link PrintWriter} that is to print {@code line}.
     * @param duplicateToStdOut Set to {@code true} if {@code line} should also be printed in standard output.
     */
    public static void println(Object line, PrintWriter writer, boolean duplicateToStdOut) {
        if (duplicateToStdOut) {
            System.out.println(line);
        }
        writer.println(line);
    }

    /**
     * Invoke {@link PrintWriter#println(Object)} passing {@code line} as argument while also printing {@code line} to
     * standard output if {@code duplicateToStdOut} is {@code true}.
     * @param line The line to be printed.
     * @param writer The {@link PrintWriter} that is to print {@code line}.
     * @param duplicateToStdOut Set to {@code true} if {@code line} should also be printed in standard output.
     */
    public static void print(Object line, PrintWriter writer, boolean duplicateToStdOut) {
        if (duplicateToStdOut) {
            System.out.print(line);
        }
        writer.print(line);
    }

    /**
     * Make writer (and standard output, if {@code duplicateToStdOut} is {@code true}) print an empty line.
     * @param writer The writer that {@link PrintWriter#println()} is to be invoked on.
     * @param duplicateToStdOut If {@code true}, prints an empty line to standard output.
     */
    public static void printEmptyLine(PrintWriter writer, boolean duplicateToStdOut) {
        if (duplicateToStdOut) {
            System.out.println();
        }
        writer.println();
    }

}
