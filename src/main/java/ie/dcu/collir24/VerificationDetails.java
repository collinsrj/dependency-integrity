package ie.dcu.collir24;

import java.util.Date;
import java.util.List;

import org.bouncycastle.openpgp.PGPPublicKey;

public class VerificationDetails {
	boolean verified;
	List<String> emails;
	long keyId;
	Date creationDate;
	PGPPublicKey key;

	@Override
	public String toString() {
		return "VerificationDetails [verified=" + verified + ", emails="
				+ emails + ", keyId=" + keyId + ", creationDate="
				+ creationDate + "]";
	}

}
