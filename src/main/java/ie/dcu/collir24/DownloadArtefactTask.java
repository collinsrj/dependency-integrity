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
 * Downloads an item from Maven
 * @author rcollins
 *
 */
public class DownloadArtefactTask implements Callable<File> {

	private static final String MAVEN_CENTRAL_URL = "http://repo1.maven.org/maven2";
	private static final Logger LOGGER = Logger
			.getLogger(DownloadArtefactTask.class.getName());
	private static final int MAX_BYTES = 10000000;// 10MB
	private final HttpClient httpClient;
	/**
	 * The path to save the file to
	 */
	private final String path;
	private final String newFilePath;

	/**
	 * 
	 * @param httpClient
	 *            an instance of {@link HttpClient}
	 * @param path
	 * @param newFilePath the path the file should be saved at.
	 */
	public DownloadArtefactTask(final HttpClient httpClient, final String path,
			final String newFilePath) {
		this.httpClient = httpClient;
		this.path = path;
		this.newFilePath = newFilePath;
	}

	/**
	 * @return returns the newly downloaded file. This may be empty.
	 */
	public File call() throws Exception {
		return getFileFromMavenCentral();
	}

	private File getFileFromMavenCentral() {
		HttpGet httpget = null;
		URI uri = getMavenCentralFileURI(path);
		HttpContext context = new BasicHttpContext();
		File newFile = null;
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
					newFile = writeFileToDisk(is, newFilePath);
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
		return newFile;
	}

	/**
	 * Creates and writes the signature file from the input
	 * 
	 * @param is
	 * @param signatureFile
	 */
	private static File writeFileToDisk(InputStream is, String path) {
		File newFile = new File(path);
		ReadableByteChannel inputChannel = Channels.newChannel(is);
		FileOutputStream os = null;
		try {
			newFile.createNewFile();
			os = new FileOutputStream(newFile);
			FileChannel outputChannel = os.getChannel();
			outputChannel.transferFrom(inputChannel, 0, MAX_BYTES);

		} catch (FileNotFoundException e) {
			throw new RuntimeException("Couldn't find file to write at path: "
					+ path, e);
		} catch (IOException e) {
			LOGGER.log(Level.WARNING, "Problem writing file: " + path, e);
		} finally {
			if (os != null) {
				try {
					os.close();
				} catch (IOException e) {
					LOGGER.warning("Couldn't close output stream for file: "
							+ path);
				}
			}
		}
		return newFile;
	}

	private static URI getMavenCentralFileURI(String path) {
		StringBuilder sb = new StringBuilder(MAVEN_CENTRAL_URL);
		sb.append(path);
		try {
			return new URI(sb.toString());
		} catch (URISyntaxException e) {
			throw new RuntimeException(
					"Problem building Maven Central URI for path: " + path, e);
		}
	}

}
