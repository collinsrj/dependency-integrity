package ie.dcu.collir24;

public class ConsoleVerificationDataStore implements VerificationDataStore {

	public void file(String path) {
		// System.out.println("file\t" + path);
	}

	public void signatureFileNotFound(String path) {
		// System.out.println("sigNotFound\t" + path);
	}

	public void couldNotParseSignature(String path) {
		System.out.println("couldnotparsesig\t" + path);
	}

	public void signedBy(String path, String keyFingerprint) {
		System.out.println("signedby\t" + keyFingerprint);
	}

	public void couldNotGetPublicKey(String fingerprint) {
		System.out.println("nopubkey\t" + fingerprint);
	}

	public void signatureVerified(String path) {
		// System.out.println("verified\t" + path);
	}

	public void signatureDidNotVerify(String path) {
		System.out.println("notverified\t" + path);
	}

	public void problemVerifying(String path) {
		System.out.println("probverifing\t" + path);
	}

	public void filesMatch(String path) {
		System.out.println("filesmatch\t" + path);
	}

	public void filesDoNotMatch(String path, String path2) {
		// System.out.println("filedonotsmatch\t" + path + "\t" + path2);
	}

	public void notInMavenCentral(String path) {
		System.out.println("notincentral\t" + path);

	}
}
