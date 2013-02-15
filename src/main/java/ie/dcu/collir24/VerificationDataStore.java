package ie.dcu.collir24;

/**
 * A store of the events that occur when
 * 
 * @author rcollins
 * 
 */
public interface VerificationDataStore {

	void file(String path);

	void signatureFileNotFound(String path);

	void couldNotParseSignature(String path);

	void signedBy(String path, String keyFingerprint);

	void couldNotGetPublicKey(String fingerprint);

	void signatureVerified(String path);

	void signatureDidNotVerify(String path);

	void problemVerifying(String path);

	void filesMatch(String path);

	void filesDoNotMatch(String path, String path2);
	
	void notInMavenCentral(String path);

}
