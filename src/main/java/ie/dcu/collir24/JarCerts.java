package ie.dcu.collir24;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.CodeSigner;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

public class JarCerts {
	private static final Set<X509Certificate> TRUSTED_CERTS = Certificates
			.getTrustedCertificates();

	public static JarVerificationDetails verifyJar(File f) throws IOException {
		JarVerificationDetails details = new JarVerificationDetails();
		JarFile jf = new JarFile(f, true, JarFile.OPEN_READ);
		Manifest manifest = jf.getManifest();
		if (manifest == null) {
			return details;
		}
		details.sealedPackages = getSealedPackages(manifest);
		getSigningDetails(details, jf);
		return details;
	}

	private static void getSigningDetails(JarVerificationDetails details,
			JarFile jf) throws IOException {
		Set<List<? extends Certificate>> certSets = new LinkedHashSet<List<? extends Certificate>>();
		Enumeration<JarEntry> entries = jf.entries();
		// A count of non directory and META-INF files
		int entriesCount = 0;
		// A count of signed entries
		int signedCount = 0;
		while (entries.hasMoreElements()) {
			JarEntry entry = entries.nextElement();
			if (entry.isDirectory() || entry.getName().startsWith("META-INF")) {
				continue;
			}
			entriesCount++;
			InputStream is = null;
			byte[] buf = new byte[4096];
			try {
				is = jf.getInputStream(entry);
				@SuppressWarnings("unused")
				int n;
				while ((n = is.read(buf, 0, buf.length)) != -1) {
					// Must read in the whole entry to get CodeSigners
					// @see JarEntry#getCodeSigners()
				}
			} finally {
				if (is != null) {
					is.close();
				}
			}
			CodeSigner[] signers = entry.getCodeSigners();
			if (signers != null && signers.length > 0) {
				details.signed = true;
				signedCount++;
				for (CodeSigner signer : signers) {
					certSets.add(signer.getSignerCertPath().getCertificates());
				}
			}
		}
		if (entriesCount == signedCount) {
			details.allEntriesSigned = true;
		}

		for (List<? extends Certificate> certs : certSets) {
			CertificatePathDetails certDetails = new CertificatePathDetails();
			if (!certs.isEmpty()) {
				// the first cert in the list is the code signer
				X509Certificate cert = (X509Certificate) certs.get(0);
				PublicKey key = cert.getPublicKey();
				certDetails.algorithm = key.getAlgorithm();
				certDetails.format = key.getFormat();
				certDetails.principal = cert.getSubjectX500Principal()
						.getName();
				certDetails.notBefore = cert.getNotBefore();
				certDetails.notAfter = cert.getNotAfter();

				// the last cert in the list should be a trusted cert
				certDetails.trusted = isTrusted((X509Certificate) certs
						.get(certs.size() - 1));
				details.certificateDetails.add(certDetails);
			}
		}
	}

	/**
	 * Checks if the Jar is sealed.
	 * 
	 * @param manifest
	 *            the jar manifest
	 * @return the list of sealed {@link Package}s, an empty list if all
	 *         packages declared in the jar are sealed or null if no packages
	 *         are sealed.
	 */

	private static List<String> getSealedPackages(Manifest manifest) {
		Attributes attributes = manifest.getMainAttributes();
		List<String> sealedPackages = null;
		String name = null;
		for (Entry<Object, Object> entry : attributes.entrySet()) {
			if ("Sealed".equals(entry.getKey().toString())) {
				if (name != null) {
					if (sealedPackages == null) {
						sealedPackages = new ArrayList<String>();
					}
					sealedPackages.add(name);
				} else {
					return Collections.emptyList();
				}
			}
			name = null;
			if ("Name".equals(entry.getKey().toString())) {
				name = entry.getValue().toString();
			}
		}
		return sealedPackages;
	}

	public static boolean isTrusted(X509Certificate cert) {
		if (TRUSTED_CERTS.contains(cert)) {
			return true;
		}
		for (X509Certificate trustedCert : TRUSTED_CERTS) {
			if (trustedCert.getSubjectX500Principal().equals(
					cert.getIssuerX500Principal())) {
				try {
					cert.verify(trustedCert.getPublicKey());
				} catch (GeneralSecurityException e) {
					return false;
				}
				return true;
			}
		}
		return false;
	}
}
