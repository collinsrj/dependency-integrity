/**
 * Code example taken from StackOverflow http://stackoverflow.com/questions/3508050/how-can-i-get-a-list-of-trusted-root-certificates-in-java
 */
package ie.dcu.collir24;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class Certificates {

	public static Set<X509Certificate> getTrustedCertificates() {
		Set<X509Certificate> certSet = new LinkedHashSet<X509Certificate>();
		certSet.addAll(getX509Certificates());
		return certSet;
	}

	public static List<X509Certificate> getX509Certificates() {
		ArrayList<X509Certificate> certs = new ArrayList<X509Certificate>();
		try {
			// Load the JDK's cacerts keystore file
			String filename = System.getProperty("java.home")
					+ "/lib/security/cacerts".replace('/', File.separatorChar);
			FileInputStream is = new FileInputStream(filename);
			KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			String password = "changeit";
			keystore.load(is, password.toCharArray());

			// This class retrieves the most-trusted CAs from the keystore
			PKIXParameters params = new PKIXParameters(keystore);

			// Get the set of trust anchors, which contain the most-trusted CA
			// certificates
			Iterator<TrustAnchor> it = params.getTrustAnchors().iterator();
			while (it.hasNext()) {
				TrustAnchor ta = it.next();
				// Get certificate
				certs.add(ta.getTrustedCert());
			}
		} catch (CertificateException e) {
		} catch (KeyStoreException e) {
		} catch (NoSuchAlgorithmException e) {
		} catch (InvalidAlgorithmParameterException e) {
		} catch (IOException e) {
		}
		// return certs.toArray(new X509Certificate[certs.size()]);
		return certs;
	}
}