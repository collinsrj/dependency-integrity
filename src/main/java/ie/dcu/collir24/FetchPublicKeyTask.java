package ie.dcu.collir24;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.Callable;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPUtil;

/**
 * Fetch the public key for a fingerprint
 * 
 * @author rcollins
 * 
 */
public class FetchPublicKeyTask implements Callable<PGPPublicKeyRing> {
	private static final Logger LOGGER = Logger
			.getLogger(FetchPublicKeyTask.class.getName());
	private final String fingerprint;
	private final HttpClient httpClient;

	public FetchPublicKeyTask(String fingerprint, HttpClient httpClient) {
		this.fingerprint = fingerprint;
		this.httpClient = httpClient;
	}

	public PGPPublicKeyRing call() throws Exception {
		URI uri = buildURI(fingerprint);
		return getPublicKeyFile(uri);
	}

	private PGPPublicKeyRing getPublicKeyFile(URI uri)
			throws ClientProtocolException, IOException {
		HttpGet httpget = null;
		HttpContext context = new BasicHttpContext();
		try {
			httpget = new HttpGet(uri);
			HttpResponse response = httpClient.execute(httpget, context);
			HttpEntity entity = response.getEntity();
			switch (response.getStatusLine().getStatusCode()) {
			case 200: {
				InputStream is = null;
				try {
					is = response.getEntity().getContent();
					return getPublicKeyFromInputStream(is);
				} finally {
					if (is != null) {
						is.close();
					}
				}
			}
			default: {
				LOGGER.warning("Unable to retrieve public key for fingerprint. HTTP status code was: "
						+ response.getStatusLine().getStatusCode()
						+ " URI requested was " + uri);
			}
			}
			EntityUtils.consume(entity);
		} catch (ClientProtocolException cpe) {
			httpget.abort();
			LOGGER.log(Level.SEVERE, "Problem getting key file.", cpe);
		}
		LOGGER.warning("Didn't get a good response from the key server.");
		return null;
	}

	private static PGPPublicKeyRing getPublicKeyFromInputStream(
			InputStream publicKeyStream) throws IOException {
		InputStream is = PGPUtil.getDecoderStream(publicKeyStream);

		PGPObjectFactory pgpFact = new PGPObjectFactory(is);
		PGPPublicKeyRing publicKeyRing = (PGPPublicKeyRing) pgpFact
				.nextObject();
		return publicKeyRing;
	}

	private static URI buildURI(String fingerprint) {
		URIBuilder builder = new URIBuilder();
		builder.setScheme("http").setHost("pgpkeys.co.uk")
				.setPath("/pks/lookup").setParameter("op", "get")
				.setParameter("options", "mr")
				.setParameter("search", fingerprint);
		try {
			return builder.build();
		} catch (URISyntaxException e) {
			throw new RuntimeException("Problem building URI for fingerprint: "
					+ fingerprint, e);
		}
	}

}
