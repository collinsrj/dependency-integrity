package ie.dcu.collir24;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.SignatureException;
import java.util.concurrent.Callable;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

/**
 * Verify the signature of the file matches that passed in
 * 
 * @author rcollins
 * 
 */
public class VerifySignatureTask implements Callable<Boolean> {

	private final PGPPublicKeyRingCollection keyRingCollection;
	private final PGPSignature sig;
	private final File f;

	/**
	 * Creates a new Task
	 * 
	 * @param keyRingCollection
	 * @param sig
	 *            the detached signature
	 * @param f
	 *            the file to check
	 */
	public VerifySignatureTask(PGPPublicKeyRingCollection keyRingCollection,
			PGPSignature sig, File f) {
		this.keyRingCollection = keyRingCollection;
		this.sig = sig;
		this.f = f;
	}

	public Boolean call() throws Exception {
		PGPPublicKey key = keyRingCollection.getPublicKey(sig.getKeyID());
		sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"),
				key);
		InputStream is = null;
		try {
			is = new BufferedInputStream(new FileInputStream(f));
			int ch;
			while ((ch = is.read()) >= 0) {
				sig.update((byte) ch);
			}
			return Boolean.valueOf(sig.verify());
		} catch (SignatureException e) {
			return false;
		} finally {
			is.close();
		}
	}

}
