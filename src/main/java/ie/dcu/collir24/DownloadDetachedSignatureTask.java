package ie.dcu.collir24;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.util.concurrent.Callable;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;

/**
 * Downloads a detached signature file from Maven Central and writes it to the
 * correct locatation in the local Maven repository
 * 
 * @author rcollins
 * 
 */
public class DownloadDetachedSignatureTask implements Callable<Boolean> {
	private static final Logger LOGGER = Logger
			.getLogger(DownloadDetachedSignatureTask.class.getName());
	private static final String MAVEN_CENTRAL_URL = "http://repo1.maven.org/maven2";

	private static final int MAX_BYTES = 1000000;
	private final String path;
	private final String signatureFilePath;
	private final HttpClient httpClient;

	/**
	 * 
	 * @param path
	 *            the path in Maven Central to the artefact
	 * @param signatureFilePath
	 *            the location on disk the detached signature is to be stored
	 * @param httpClient
	 */
	public DownloadDetachedSignatureTask(String path, String signatureFilePath,
			HttpClient httpClient) {
		this.path = path;
		this.signatureFilePath = signatureFilePath;
		this.httpClient = httpClient;
	}

	public Boolean call() throws Exception {
		return Boolean.valueOf(getSignatureFileFromMavenCentral());
	}

	private boolean getSignatureFileFromMavenCentral() {
		boolean retrievedFileFromMavenCentral = false;
		HttpGet httpget = null;
		HttpContext context = new BasicHttpContext();
		URI uri = getMavenCentralSignatureURI(path);
		try {
			httpget = new HttpGet(uri);
			HttpResponse response = httpClient.execute(httpget, context);
			HttpEntity entity = response.getEntity();
			int statusCode = response.getStatusLine().getStatusCode();
			switch (statusCode) {
			case 200: {
				InputStream is = null;
				try {
					is = response.getEntity().getContent();
					retrievedFileFromMavenCentral = writeSignatureFileToDisk(
							is, signatureFilePath);
				} finally {
					if (is != null) {
						is.close();
					}
				}
				break;
			}
			case 404: {
				LOGGER.fine("Didn't find signature file on Maven Central at URI: "
						+ uri);
				break;
			}
			default:
				LOGGER.warning("Unexpected response code when downloading signature file from URI: "
						+ uri);
			}
			EntityUtils.consume(entity);
		} catch (ClientProtocolException cpe) {
			httpget.abort();
			LOGGER.log(Level.SEVERE,
					"Problem getting signature file from URI: " + uri, cpe);
		} catch (IOException e) {
			httpget.abort();
			LOGGER.log(Level.SEVERE,
					"Problem getting signature file from URI: " + uri, e);
		}
		return retrievedFileFromMavenCentral;
	}

	/**
	 * Creates and writes the signature file from the input
	 * 
	 * @param is
	 * @param signatureFile
	 */
	private static boolean writeSignatureFileToDisk(InputStream is, String path) {
		File signatureFile = new File(path);
		ReadableByteChannel inputChannel = Channels.newChannel(is);
		FileOutputStream os = null;
		try {
			signatureFile.createNewFile();
			os = new FileOutputStream(signatureFile);
			FileChannel outputChannel = os.getChannel();
			outputChannel.transferFrom(inputChannel, 0, MAX_BYTES);
			return true;
		} catch (FileNotFoundException e) {
			throw new RuntimeException("Couldn't find file to write at path: "
					+ path, e);
		} catch (IOException e) {
			LOGGER.log(Level.WARNING, "Problem writing file: " + path, e);
			return false;
		} finally {
			if (os != null) {
				try {
					os.close();
				} catch (IOException e) {
					LOGGER.warning("Couldn't close output stream for signature file: "
							+ path);
				}
			}
		}
	}

	private static URI getMavenCentralSignatureURI(String path) {
		StringBuilder sb = new StringBuilder(MAVEN_CENTRAL_URL);
		sb.append(path);
		sb.append(".asc");
		try {
			return new URI(sb.toString());
		} catch (URISyntaxException e) {
			throw new RuntimeException(
					"Problem building Maven Central URI for path: " + path, e);
		}
	}
}
