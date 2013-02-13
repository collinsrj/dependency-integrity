package ie.dcu.collir24;

import java.io.File;
import java.io.FilenameFilter;
import java.util.regex.Pattern;

public class SignedFilenameFilter implements FilenameFilter {

	/**
	 * Match common files in the Maven repo
	 */
	private static final Pattern EXTENSION_PATTERN = Pattern
			.compile("\\.jar$|\\.ear$|\\.war$|\\.pom$");

	public boolean accept(File arg0, String arg1) {
		return EXTENSION_PATTERN.matcher(arg1).find();
	}

}
