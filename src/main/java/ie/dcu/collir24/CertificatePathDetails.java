package ie.dcu.collir24;
import java.util.Date;

public class CertificatePathDetails {
	String algorithm;
	String principal;
	String format;
	Date notAfter;
	Date notBefore;
	/**
	 * Whether the jar file has been signed by a trusted root CA
	 */
	boolean trusted = false;

	@Override
	public String toString() {
		return "CertificatePathDetails [algorithm=" + algorithm
				+ ", principal=" + principal + ", format=" + format
				+ ", notAfter=" + notAfter + ", notBefore=" + notBefore
				+ ", trusted=" + trusted + "]";
	}
}
