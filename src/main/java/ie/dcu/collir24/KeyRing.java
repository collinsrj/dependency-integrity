package ie.dcu.collir24;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;

/**
 * A thread safe key ring.
 * 
 * @author rcollins
 * 
 */
public class KeyRing {
	private static final Logger LOGGER = Logger.getLogger(KeyRing.class
			.getName());
	private final String keyRingFile;
	private PGPPublicKeyRingCollection keyRingCollection;

	public KeyRing(String keyRingFile) {
		this.keyRingFile = keyRingFile;
		try {
			keyRingCollection = new PGPPublicKeyRingCollection(
					PGPUtil.getDecoderStream(new FileInputStream(keyRingFile)));
		} catch (FileNotFoundException e) {
			throw new RuntimeException("Couldn't find keyring file.");
		} catch (IOException e) {
			throw new RuntimeException("Problem reading keyring file.", e);
		} catch (PGPException e) {
			throw new RuntimeException("Problem reading keyring file.", e);
		}
	}

	private final ReentrantReadWriteLock rwl = new ReentrantReadWriteLock();
	private final Lock r = rwl.readLock();
	private final Lock w = rwl.writeLock();

	/**
	 * Check if the key ring contains
	 * 
	 * @return
	 */
	boolean contains(long keyId) {
		r.lock();
		try {
			return keyRingCollection.contains(keyId);
		} catch (PGPException e) {
			throw new RuntimeException(
					"Problem checking keyring contains with keyId: " + keyId);
		} finally {
			r.unlock();
		}
	}

	/**
	 * Adds a public key to the key ring.
	 * 
	 * @param publicKeyRing
	 */
	void addKey(PGPPublicKeyRing publicKeyRing) {
		w.lock();
		try {
			if (!keyRingCollection.contains(publicKeyRing.getPublicKey().getKeyID())) {
				keyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(
						keyRingCollection, publicKeyRing);	
			}			
		} catch (PGPException e) {
			throw new RuntimeException(
					"Problem checking keyring contains with keyId: " + publicKeyRing.getPublicKey().getKeyID());
		} finally {
			w.unlock();
		}
	}

	PGPPublicKey getPublicKey(long keyId) {
		r.lock();
		try {
			return keyRingCollection.getPublicKey(keyId);
		} catch (PGPException e) {
			throw new RuntimeException(
					"Problem getting public key with keyId: " + keyId);
		} finally {
			r.unlock();
		}
	}

	void save() {
		w.lock();
		try {
			FileOutputStream newPubKeyring = null;
			try {
				newPubKeyring = new FileOutputStream(keyRingFile);
				keyRingCollection.encode(newPubKeyring);
			} catch (IOException e) {
				throw new RuntimeException("Problem saving keyring file at: "
						+ e);
			} finally {
				if (newPubKeyring != null) {
					try {
						newPubKeyring.close();
					} catch (IOException e) {
						LOGGER.log(Level.SEVERE,
								"Problems closing keyring save.", e);
					}
				}
			}
		} finally {
			w.unlock();
		}
	}
}
