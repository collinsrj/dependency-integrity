package ie.dcu.collir24;
import java.util.ArrayList;
import java.util.List;

public class JarVerificationDetails {

	/**
	 * Whether any entries in the jar file have been signed
	 */
	boolean signed = false;
	boolean allEntriesSigned = false;
	/**
	 * A list of sealed packages. This will be null if no packages are sealed,
	 * empty if all are sealed and not empty if specific packages are sealed
	 */
	List<String> sealedPackages = null;
	/**
	 * A list of certificate paths used in code signing
	 */
	List<CertificatePathDetails> certificateDetails = new ArrayList<CertificatePathDetails>();

	@Override
	public String toString() {
		return "JarVerificationDetails [signed=" + signed
				+ ", allEntriesSigned=" + allEntriesSigned
				+ ", sealedPackages=" + sealedPackages
				+ ", certificateDetails=" + certificateDetails + "]";
	}

}
