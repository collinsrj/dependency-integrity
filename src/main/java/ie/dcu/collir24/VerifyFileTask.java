package ie.dcu.collir24;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.io.FileUtils;
import org.apache.http.client.HttpClient;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

public class VerifyFileTask implements Runnable {
	private static final Logger LOGGER = Logger.getLogger(VerifyFileTask.class
			.getName());
	private final File file;
	private final ExecutorService exec;
	private final HttpClient httpClient;
	private final String mavenRepoPath;
	private final KeyRing keyRing;
	private final VerificationDataStore dataStore;
	private static final int MAX_WAIT_SECONDS = 30;

	public VerifyFileTask(final File file, final ExecutorService exec,
			final HttpClient httpClient, final String mavenRepoPath,
			final KeyRing keyRing, final VerificationDataStore dataStore) {
		this.file = file;
		this.exec = exec;
		this.httpClient = httpClient;
		this.mavenRepoPath = mavenRepoPath;
		this.keyRing = keyRing;
		this.dataStore = dataStore;
	}

	public void run() {
		String filePath = file.getAbsolutePath();
		String signatureFile = "";
		try {
			signatureFile = getSignatureFile(file);
		} catch (IOException e) {
			LOGGER.log(Level.WARNING,
					"Problem getting signature file: " + file, e);
		}
		if (signatureFile == null || signatureFile.isEmpty()) {
			dataStore.signatureFileNotFound(filePath);
			return;
		}
		PGPSignature signature;
		try {
			signature = getPGPSignatureFromString(signatureFile);
		} catch (IOException e) {
			dataStore.couldNotParseSignature(filePath);
			return;
		} catch (PGPException e) {
			dataStore.couldNotParseSignature(filePath);
			return;
		}
		if (!keyRing.contains(signature.getKeyID())) {
			String fingerprint = getKeyIdFingerPrint(signature);
			PGPPublicKeyRing publicKey = getPublicKey(fingerprint);
			if (publicKey != null) {
				keyRing.addKey(publicKey);
			} else {
				dataStore.couldNotGetPublicKey(fingerprint);
				return;
			}
		}

		try {
			boolean verified = verifySignature(file, signature);
			if (verified) {
				dataStore.signatureVerified(filePath);
			} else {
				dataStore.signatureDidNotVerify(filePath);
				if (filesDifferent()) {
					dataStore.filesMatch(filePath);
				}
			}
		} catch (IOException e) {
			dataStore.problemVerifying(filePath);
			return;
		} catch (PGPException e) {
			dataStore.problemVerifying(filePath);
			return;
		}

	}

	/**
	 * Checks to see if the original file and the file on Maven are different
	 * 
	 * @return
	 */
	private boolean filesDifferent() {
		String absolutePath = file.getAbsolutePath();
		String path = absolutePath.substring(mavenRepoPath.length());
		String newFilePath = String.format("%s.%tF", absolutePath,
				System.currentTimeMillis());
		File newFile = null;
		try {
			newFile = exec.submit(
					new DownloadArtefactTask(httpClient, path, newFilePath))
					.get();
		} catch (InterruptedException e) {
			Thread.interrupted();
		} catch (ExecutionException e) {
			return false;
		}
		boolean match = false;
		if (newFile == null) {
			dataStore.notInMavenCentral(newFilePath);
		} else {
			byte[] sha1File1 = createSha1(file);
			byte[] sha1File2 = createSha1(newFile);
			match = Arrays.equals(sha1File1, sha1File2);
			if (match) {
				dataStore.filesMatch(path);
			} else {
				dataStore.filesDoNotMatch(path, newFilePath);
			}
		}
		return match;
	}

	private PGPPublicKeyRing getPublicKey(String fingerprint) {
		Future<PGPPublicKeyRing> fetchPublicKeyFuture = exec
				.submit(new FetchPublicKeyTask(fingerprint, httpClient));
		try {
			return fetchPublicKeyFuture.get(MAX_WAIT_SECONDS, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		} catch (ExecutionException e) {
			LOGGER.log(Level.WARNING,
					"Problem trying to retrieve public key for fingerprint: "
							+ fingerprint, e);
		} catch (TimeoutException e) {
			LOGGER.log(Level.WARNING,
					"Timed out waiting for public key for fingerprint: "
							+ fingerprint, e);
		}
		return null;
	}

	private String getSignatureFile(File f) throws IOException {
		String absolutePath = f.getAbsolutePath();
		String signatureFilePath = absolutePath + ".asc";
		String signatureNotFoundFilePath = absolutePath + ".asc.not_found";
		File signatureFile = new File(signatureFilePath);
		File signatureNotFoundFile = new File(signatureNotFoundFilePath);
		if (signatureFile.exists()) {
			return FileUtils.readFileToString(signatureFile);
		} else if (signatureNotFoundFile.exists()) {
			LOGGER.finer("Already checked for signature file and didn't find it.");
			return "";
		} else {
			String path = absolutePath.substring(mavenRepoPath.length());
			Future<Boolean> downloadSignatureFuture = exec
					.submit(new DownloadDetachedSignatureTask(path,
							signatureFilePath, httpClient));
			try {
				boolean retrievedFile = downloadSignatureFuture.get(
						MAX_WAIT_SECONDS, TimeUnit.SECONDS).booleanValue();
				if (retrievedFile) {
					return FileUtils.readFileToString(signatureFile);
				} else {
					FileUtils.writeStringToFile(signatureNotFoundFile,
							String.format("%tc", new Date()),
							Charset.forName("UTF-8"));
				}
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			} catch (ExecutionException e) {
				LOGGER.log(Level.WARNING,
						"Problem trying to retrieve signature file for: "
								+ path, e);
			} catch (TimeoutException e) {
				LOGGER.fine("Timed out trying to get the signature file for: "
						+ path);
			}
			return "";
		}
	}

	/**
	 * Get the signature from the text
	 * 
	 * @param signatureText
	 * @return
	 * @throws IOException
	 * @throws PGPException
	 */
	protected static PGPSignature getPGPSignatureFromString(String signatureText)
			throws IOException, PGPException {
		InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(
				signatureText.getBytes("UTF-8")));
		PGPObjectFactory pgpFact = new PGPObjectFactory(in);
		PGPSignatureList p3;
		Object o = pgpFact.nextObject();
		if (o == null) {
			throw new IOException("Couldn't parse signature file");
		}
		if (o instanceof PGPCompressedData) {
			PGPCompressedData c1 = (PGPCompressedData) o;

			pgpFact = new PGPObjectFactory(c1.getDataStream());

			p3 = (PGPSignatureList) pgpFact.nextObject();
		} else {
			p3 = (PGPSignatureList) o;
		}
		return p3.get(0);
	}

	/**
	 * Get the fingerprint for a key ID from a signature
	 * 
	 * @param signature
	 * @return the 8 character hex fingerprint e.g. 0x70C9C3D0
	 */
	private static String getKeyIdFingerPrint(PGPSignature signature) {
		String keyAsHex = Long.toHexString(signature.getKeyID()).toUpperCase();
		String fingerPrint = "0x" + keyAsHex.substring(keyAsHex.length() - 8);
		assert fingerPrint.length() == 10;
		return fingerPrint;
	}

	private boolean verifySignature(File f, PGPSignature sig)
			throws IOException, PGPException {
		PGPPublicKey key = keyRing.getPublicKey(sig.getKeyID());
		sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"),
				key);
		InputStream is = null;
		try {
			is = new BufferedInputStream(new FileInputStream(f));
			int ch;
			while ((ch = is.read()) >= 0) {
				sig.update((byte) ch);
			}
			return sig.verify();
		} catch (SignatureException e) {
			LOGGER.log(Level.FINE, "Signature Problem", e);
			return false;
		} finally {
			is.close();
		}

	}

	private static byte[] createSha1(File file) {
		if (file == null || !file.exists()) {
			throw new IllegalArgumentException("File doesn't exist: " + file);
		}
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Couldn't create digest algorithm.", e);
		}
		InputStream fis = null;
		try {
			fis = new FileInputStream(file);

			int n = 0;
			byte[] buffer = new byte[1024];
			while (n != -1) {
				n = fis.read(buffer);
				if (n > 0) {
					digest.update(buffer, 0, n);
				}
			}
		} catch (FileNotFoundException e) {
			throw new IllegalStateException("File doesn't exist: " + file, e);
		} catch (IOException e) {
			throw new IllegalStateException("Problem reading file: " + file, e);
		} finally {
			if (fis != null) {
				try {
					fis.close();
				} catch (IOException e) {
					LOGGER.log(Level.SEVERE, "Couldn't close file: " + file, e);
				}
			}
		}
		return digest.digest();
	}
}
