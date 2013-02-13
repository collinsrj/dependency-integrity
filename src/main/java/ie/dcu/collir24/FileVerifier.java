package ie.dcu.collir24;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.Collection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.FileFilterUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
/**
 * Verifies the integrity of files in a local Maven repository. It does this by downloading the detached signature file from Maven Central.   
 * @author rcollins
 *
 */
public class FileVerifier {

	private static final String M2_REPOSITORY;
	private static final Logger LOGGER = Logger.getLogger(FileVerifier.class
			.getName());
	private static final String NEW_PUBLIC_KEYRING_FILE = "/Users/rcollins/.gnupg/pubring_new.gpg";
	private final ExecutorService exec = Executors.newFixedThreadPool(4);
	private final ExecutorService webExec = Executors.newFixedThreadPool(8);
	private HttpClient httpClient;
	private final KeyRing keyRing;

	public FileVerifier() {
		Security.addProvider(new BouncyCastleProvider());
		InputStream loggingProperties = FileVerifier.class
				.getResourceAsStream("logging.properties");
		try {
			LogManager.getLogManager().readConfiguration(loggingProperties);
		} catch (SecurityException e) {
			LOGGER.log(Level.SEVERE,
					"Problem reading logging properties file.", e);
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE,
					"Problem reading logging properties file.", e);
		} finally {
			try {
				loggingProperties.close();
			} catch (IOException e) {
				LOGGER.warning("Can't close logging properties file.");
			}
		}
		this.keyRing = new KeyRing(NEW_PUBLIC_KEYRING_FILE);
		PoolingClientConnectionManager cm = new PoolingClientConnectionManager();
		cm.setDefaultMaxPerRoute(4);// increase from the default of 2
		httpClient = new DefaultHttpClient(cm);
	}

	static {
		String m2HomeEnv = System.getenv("M2_HOME");
		String userHome = System.getProperties().getProperty("user.home");
		M2_REPOSITORY = m2HomeEnv != null && !m2HomeEnv.isEmpty() ? m2HomeEnv
				: userHome + "/.m2/repository";
	}

	public static void main(String[] args) {
		FileVerifier verifier = new FileVerifier();
		verifier.verifyFiles();
	}

	private void verifyFiles() {
		File repoFile = new File(M2_REPOSITORY);
		Collection<File> files = FileUtils.listFiles(repoFile,
				FileFilterUtils.asFileFilter(new SignedFilenameFilter()),
				TrueFileFilter.INSTANCE);
		VerificationDataStore dataStore = new ConsoleVerificationDataStore();
		for (File f : files) {
			exec.execute(new VerifyFileTask(f, webExec, httpClient,
					M2_REPOSITORY, keyRing, dataStore));
		}
		shutdownExecutors();
	}

	private void shutdownExecutors() {
		boolean shutdown = false;
		try {
			exec.shutdown();
			shutdown = exec.awaitTermination(4, TimeUnit.HOURS);
			if (shutdown) {
				webExec.shutdown();
			}
		} catch (InterruptedException e) {
			Thread.interrupted();
		} finally {
			exec.shutdownNow();
			webExec.shutdownNow();
			httpClient.getConnectionManager().shutdown();
		}
	}

}
