package ie.dcu.collir24;

import java.io.IOException;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

public class LoggingVerificationDataStore implements VerificationDataStore {
	private final FileHandler fileHandler;

	public LoggingVerificationDataStore() {
		try {
			fileHandler = new FileHandler("MavenVerification.log");
		} catch (IOException ex) {
			LOGGER.log(Level.SEVERE, null, ex);
			throw new RuntimeException(ex);
		} catch (SecurityException ex) {
			LOGGER.log(Level.SEVERE, null, ex);
			throw new RuntimeException(ex);
		}
		LOGGER.addHandler(fileHandler);
	}

	private static final Logger LOGGER = Logger
			.getLogger(LoggingVerificationDataStore.class.getName());

	public void file(String path) {
		LOGGER.info("File: " + path);
	}

	public void signatureFileNotFound(String path) {
		LOGGER.info("signatureFileNotFound: " + path);
	}

	public void couldNotParseSignature(String path) {
		LOGGER.info("couldNotParseSignature: " + path);
	}

	public void signedBy(String path, String keyFingerprint) {
		LOGGER.info(path + " signedBy: " + keyFingerprint);
	}

	public void signatureVerified(String path) {
		LOGGER.info("signatureVerified: " + path);
	}

	public void signatureDidNotVerify(String path) {
		LOGGER.info("signatureDidNotVerify: " + path);
	}

	public void couldNotGetPublicKey(String fingerprint) {
		LOGGER.info("couldNotGetPublicKey: " + fingerprint);
	}

	public void problemVerifying(String path) {
		LOGGER.info("problemVerifying: " + path);
	}

	public void filesMatch(String path) {
		LOGGER.info("filesMatch: " + path);
	}

	public void filesDoNotMatch(String path, String path2) {
		LOGGER.info("filesDoNotMatch: " + path + " " + path2);
	}
}
