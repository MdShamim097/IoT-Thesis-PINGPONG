import java.io.File;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.io.IOException;

public class DateWriter {

	public static void main(String[] args) throws IOException {
		if (args.length < 3) {
			System.out.println("Usage: java " + DateWriter.class.getSimpleName() + " /path/to/file/with/timestamps /path/to/new/timestamp/file/with/dates initial_date_in_MM/dd/uuuu_format");
			System.exit(1);
		}
		String pathOriginal = args[0];
		String pathModified = args[1];
		String initialDateStr = args[2];
		DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("MM/dd/uuuu");
		LocalDate date = LocalDate.parse(initialDateStr, dateFormatter);
		File originalFile = new File(pathOriginal);
		// Create output file
		File modifiedFile = new File(pathModified);
		modifiedFile.createNewFile();
		BufferedReader reader = new BufferedReader(new FileReader(originalFile));
		PrintWriter writer = new PrintWriter(modifiedFile);
		String line = null;
		String prevLine = null;
		while ((line = reader.readLine()) != null) {
			if (isNewDay(line, prevLine)) {
				// Advance date
				date = date.plusDays(1);
			}
			writer.println(String.format("%s %s", date.format(dateFormatter), line));
			prevLine = line;
		}
		writer.flush();
		writer.close();
		reader.close();
	}

	private static boolean isNewDay(String line, String prevLine) {
		if (prevLine == null) {
			return false;
		}
		// First part handles case where we pass midnight and the following timestamp is an AM timestamp
		// Second case handles case where we pass midnight, but the following timestamp is a PM timestamp
		return line.endsWith("AM") && prevLine.endsWith("PM") || toLocalTime(line).isBefore(toLocalTime(prevLine));
	}

	private static LocalTime toLocalTime(String timeString) {
		return LocalTime.parse(timeString, DateTimeFormatter.ofPattern("h:mm:ss a"));
	}
}