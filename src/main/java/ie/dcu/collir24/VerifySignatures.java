package ie.dcu.collir24;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.StringWriter;
import java.security.Security;
import java.security.SignatureException;
import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.IOFileFilter;
import org.apache.commons.io.filefilter.RegexFileFilter;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.h2.jdbcx.JdbcConnectionPool;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;
import org.jdom2.Namespace;
import org.jdom2.input.SAXBuilder;
import org.jdom2.input.sax.XMLReaders;

/**
 * A standalone class to verify signatures
 * 
 * @author rcollins
 * 
 */
public class VerifySignatures {
	private final String path;
	private static final SAXBuilder BUILDER = new SAXBuilder(
			XMLReaders.NONVALIDATING);
	private static final Logger LOGGER = Logger
			.getLogger(VerifySignatures.class.getName());
	private static final IOFileFilter NAME_FILTER = new RegexFileFilter(
			"^.*\\.(pom|jar)$");
	private static final String NEW_PUBLIC_KEYRING_FILE;
	private static final String DATABASE_PATH;
	private final KeyRing keyRing;
	private final JcaPGPContentVerifierBuilderProvider provider = new JcaPGPContentVerifierBuilderProvider();
	private final JdbcConnectionPool cp = JdbcConnectionPool.create("jdbc:h2:"
			+ DATABASE_PATH, "sa", "sa");
	private final ExecutorService exec = Executors.newCachedThreadPool();
	private final HttpClient httpClient = new DefaultHttpClient(
			new PoolingClientConnectionManager());
	/**
	 * Keys IDs which we cannot get from keyserver
	 */
	private final Set<Long> badKeys = new HashSet<Long>();

	public VerifySignatures(final String path) {
		Security.addProvider(new BouncyCastleProvider());
		this.keyRing = new KeyRing(NEW_PUBLIC_KEYRING_FILE);
		this.path = path;
		this.provider.setProvider("BC");
		try {
			initDb();
		} catch (SQLException e) {
			throw new RuntimeException("Couldn't init db", e);
		}
	}

	static {
		String userHome = System.getProperties().getProperty("user.home");
		NEW_PUBLIC_KEYRING_FILE = userHome + "/.gnupg/pubring.gpg";
		DATABASE_PATH = "verification_db";
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		if (args.length != 1) {
			System.out
					.println("Usage: java ie.dcu.collir24.VerifySignatures <path>");
			return;
		}
		VerifySignatures verify = new VerifySignatures(args[0]);
		verify.verifySignatures();
		verify.shutdown();
	}

	private void shutdown() {
		exec.shutdown();
	}

	private void verifySignatures() {
		Collection<File> files = FileUtils.listFiles(new File(path),
				NAME_FILTER, TrueFileFilter.INSTANCE);
		int size = files.size();
		int current = 0;
		LOGGER.info("There are :" + size + " files.");
		for (File file : files) {
			current++;
			try {
				String sigPath = file.getAbsolutePath() + ".asc";
				File sigFile = new File(sigPath);
				long fileId = persistFile(file);
				if (file.getName().endsWith(".pom")) {
					MavenDetails mavenDetails = getMavenDetails(file);
					persistPom(mavenDetails, fileId);
				}

				if (file.getName().endsWith(".jar")) {
					// verify the signed jar file
					JarVerificationDetails jarDetails = JarCerts
							.verifyJar(file);
					persistJar(jarDetails, fileId);
				}

				VerificationDetails verificationDetails = null;
				if (sigFile.exists()) {
					verificationDetails = verifySignature(file, sigFile);
					persistDetails(verificationDetails, fileId);
				}
			} catch (JDOMException e) {
				persistError(file, e);
			} catch (IOException e) {
				persistError(file, e);
			} catch (PGPException e) {
				persistError(file, e);
			} catch (SQLException e) {
				LOGGER.log(Level.SEVERE, "SQL Issue", e);
				throw new RuntimeException(e);
			} catch (Exception e) {
				persistError(file, e);
			}
			if (current % 5000 == 0) {
				LOGGER.info("Now on:" + current);
			}
		}
	}

	private VerificationDetails verifySignature(File file, File sigFile)
			throws IOException, PGPException {
		VerificationDetails details = new VerificationDetails();
		PGPSignature sig = getPGPSignature(sigFile);
		details.keyId = sig.getKeyID();
		details.creationDate = sig.getCreationTime();
		PGPPublicKey key = keyRing.getPublicKey(sig.getKeyID());
		long keyId = sig.getKeyID();
		if (key == null) {
			String keyAsHex = Long.toHexString(keyId).toUpperCase();
			String fingerprint = "0x"
					+ keyAsHex.substring(keyAsHex.length() - 8);
			if (badKeys.contains(keyId)) {
				throw new PGPException("Can't retrieve key with fingerprint: "
						+ fingerprint);
			}
			try {
				PGPPublicKeyRing newKey = exec.submit(
						new FetchPublicKeyTask(fingerprint, httpClient)).get(
						10, TimeUnit.SECONDS);
				if (newKey == null) {
					badKeys.add(keyId);
					throw new PGPException(
							"Can't retrieve key with fingerprint: "
									+ fingerprint);
				}
				keyRing.addKey(newKey);
				key = keyRing.getPublicKey(sig.getKeyID());
			} catch (InterruptedException e) {
				Thread.interrupted();
			} catch (ExecutionException e) {
				badKeys.add(keyId);
				throw new PGPException("Can't retrieve key with fingerprint: "
						+ fingerprint);
			} catch (TimeoutException e) {
				badKeys.add(keyId);
				throw new PGPException("Can't retrieve key with fingerprint: "
						+ fingerprint, e);
			}
		}
		details.key = key;
		try {
			sig.init(provider, key);
		} catch (NullPointerException e) {
			throw new PGPException("Problem with sig init.", e);
		}

		InputStream is = null;
		try {
			is = new BufferedInputStream(new FileInputStream(file));
			int ch;
			while ((ch = is.read()) >= 0) {
				sig.update((byte) ch);
			}
			details.verified = Boolean.valueOf(sig.verify());
		} catch (SignatureException e) {
			details.verified = false;
		} finally {
			is.close();
		}
		return details;
	}

	private static PGPSignature getPGPSignature(File sigFile)
			throws IOException, PGPException {
		InputStream in = PGPUtil.getDecoderStream(new BufferedInputStream(
				new FileInputStream(sigFile)));
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

	private static MavenDetails getMavenDetails(File file)
			throws JDOMException, IOException {
		Reader reader = null;
		try {
			Document doc = BUILDER.build(new InputStreamReader(new FileInputStream(
					file), "UTF-8"));
			Element project = doc.getRootElement();
			Namespace ns = project.getNamespace();
			Element modelVersion = project.getChild("modelVersion", ns);
			if (modelVersion == null) {
				return getMaven3Details(project, ns, file);
			} else {
				return getMaven4Details(project, ns);
			}
		} finally {
			if (reader != null) {
				reader.close();
			}
		}
	}

	private static MavenDetails getMaven3Details(Element project, Namespace ns,
			File file) {
		String groupId = project.getChildTextTrim("name", ns);
		String artifactId = project.getChildTextTrim("id", ns);
		String version = file.getName();
		return new MavenDetails(3, groupId, artifactId, version);
	}

	private static MavenDetails getMaven4Details(Element project, Namespace ns) {
		String groupId = project.getChildTextTrim("groupId", ns);
		if (groupId == null || groupId.isEmpty()) {
			Element parent = project.getChild("parent", ns);
			groupId = parent.getChildTextTrim("groupId", ns);
		}
		String artifactId = project.getChildTextTrim("artifactId", ns);
		String version = project.getChildTextTrim("version", ns);
		
		MavenDetails details = new MavenDetails(4, groupId, artifactId, version);
		setScm(project, ns, details);
		setDevelopers(project, ns, details);
		return details;
	}

	private static void setScm(Element project, Namespace ns,
			MavenDetails details) {
		Element scm = project.getChild("scm");
		if (scm != null) {
			String url = scm.getChildText("url", ns);
			String connection = scm.getChildText("connection", ns);
			String developerConnection = scm.getChildText(
					"developerConnection", ns);
			details.setScm(new SCM(url, connection, developerConnection));
		}
	}

	private static void setDevelopers(Element project, Namespace ns,
			MavenDetails details) {
		Element developers = project.getChild("developers", ns);
		if (developers != null) {
			List<Element> developerList = developers.getChildren("developer",
					ns);
			for (Element developer : developerList) {
				if (developer.getChild("email", ns) != null) {
					details.getDeveloperEmails().add(
							developer.getChildText("email", ns).trim()
									.toLowerCase());
				}
			}
		}
	}

	private void initDb() throws SQLException {
		Connection c = null;
		Statement create = null;
		try {
			c = cp.getConnection();
			create = c.createStatement();
			create.addBatch("CREATE TABLE IF NOT EXISTS FILE(ID INT PRIMARY KEY AUTO_INCREMENT, FILE_PATH VARCHAR NOT NULL UNIQUE);");
			create.addBatch("CREATE TABLE IF NOT EXISTS MAVEN_POM(ID INT PRIMARY KEY, GROUP_ID VARCHAR, ARTIFACT_ID VARCHAR, VERSION VARCHAR, POM_VERSION TINYINT);");
			create.addBatch("CREATE TABLE IF NOT EXISTS JAR(ID INT PRIMARY KEY, SIGNED BOOLEAN NOT NULL, ALL_ENTRIES_SIGNED BOOLEAN, SEALED BOOLEAN NOT NULL);");
			create.addBatch("CREATE TABLE IF NOT EXISTS JAR_SEALED_PACKAGES(ID INT PRIMARY KEY AUTO_INCREMENT, FILE_ID INT NOT NULL, PACKAGE VARCHAR);");
			create.addBatch("CREATE TABLE IF NOT EXISTS JAR_CERT_PATHS(ID INT PRIMARY KEY AUTO_INCREMENT, FILE_ID INT NOT NULL, ALGORITHM VARCHAR, PRINCIPAL VARCHAR, FORMAT VARCHAR, NOT_BEFORE TIMESTAMP, NOT_AFTER TIMESTAMP, TRUSTED BOOLEAN NOT NULL);");
			create.addBatch("CREATE TABLE IF NOT EXISTS DEVELOPERS(ID INT PRIMARY KEY AUTO_INCREMENT, MAVEN_POM_ID INT, EMAIL VARCHAR);");
			create.addBatch("CREATE TABLE IF NOT EXISTS SIGNATURE(ID INT PRIMARY KEY AUTO_INCREMENT, FILE_ID INT NOT NULL, CREATE_TIME TIMESTAMP, VERIFIED BOOLEAN, KEY_ID BIGINT);");
			create.addBatch("CREATE TABLE IF NOT EXISTS PUBLIC_KEY(ID INT PRIMARY KEY AUTO_INCREMENT, KEY_ID BIGINT UNIQUE, CREATE_TIME TIMESTAMP, EXPIRY_TIME TIMESTAMP, ALGORITHM CHAR(9), BIT_STRENGTH INT, REVOKED BOOLEAN);");
			create.addBatch("CREATE TABLE IF NOT EXISTS PUBLIC_KEY_USER(ID INT PRIMARY KEY AUTO_INCREMENT, PUBLIC_KEY_ID INT, UID VARCHAR);");
			create.addBatch("CREATE TABLE IF NOT EXISTS ERRORS(ID INT PRIMARY KEY AUTO_INCREMENT, FILE_PATH VARCHAR, MESSAGE VARCHAR, STACK_TRACE VARCHAR, NOTES VARCHAR);");

			create.addBatch("CREATE INDEX IF NOT EXISTS IDX_JAR_ID ON JAR_SEALED_PACKAGES(FILE_ID);");
			create.addBatch("CREATE INDEX IF NOT EXISTS IDX_FILE_ID ON SIGNATURE(FILE_ID);");
			create.addBatch("CREATE INDEX IF NOT EXISTS IDX_KEY_ID ON PUBLIC_KEY(KEY_ID);");
			create.addBatch("CREATE INDEX IF NOT EXISTS IDX_UID ON PUBLIC_KEY_USER(UID);");
			create.addBatch("CREATE INDEX IF NOT EXISTS IDX_JAR_ID_CP ON JAR_CERT_PATHS(FILE_ID);");
			create.addBatch("CREATE UNIQUE INDEX IF NOT EXISTS IDX_FILE_PATH ON FILE(FILE_PATH);");
			int[] result = create.executeBatch();
			for (int i = 0; i < result.length; i++) {
				if (result[i] == Statement.EXECUTE_FAILED) {
					throw new IllegalStateException(
							"Failed to create the database");
				}
			}
		} finally {
			if (create != null) {
				create.close();
			}
			if (c != null) {
				c.close();
			}
		}
		//
	}

	private long persistFile(File file) throws SQLException {
		Connection c = null;
		PreparedStatement insertFile = null;
		try {
			c = cp.getConnection();
			String filePath = file.getAbsolutePath().substring(path.length());
			insertFile = persistFile(filePath, c);
			ResultSet fileId = insertFile.getGeneratedKeys();
			if (fileId.first()) {
				return fileId.getLong(1);
			} else {
				throw new SQLException("Didn't get back insert ID");
			}
		} finally {
			if (insertFile != null) {
				insertFile.close();
			}
			if (c != null) {
				c.close();
			}
		}
	}

	private PreparedStatement persistFile(String filePath, Connection c)
			throws SQLException {
		PreparedStatement insertPom;
		insertPom = c
				.prepareStatement("INSERT INTO FILE(FILE_PATH) VALUES (?)");
		insertPom.setString(1, filePath);
		insertPom.execute();
		return insertPom;
	}

	private void persistPom(MavenDetails mavenDetails, long fileId)
			throws SQLException {
		Connection c = null;
		PreparedStatement insertPom = null;
		try {
			c = cp.getConnection();
			insertPom = persistPom(fileId, mavenDetails, c);
			persistDevelopers(c, fileId, mavenDetails.getDeveloperEmails());
		} finally {
			if (insertPom != null) {
				insertPom.close();
			}
			if (c != null) {
				c.close();
			}
		}
	}

	private void persistJar(JarVerificationDetails jarDetails, long fileId)
			throws SQLException {
		Connection c = null;
		try {
			c = cp.getConnection();
			persistJar(fileId, jarDetails, c);
			if (jarDetails.sealedPackages != null) {
				persistSealedPackages(fileId, jarDetails, c);
			}
			persistCertPaths(fileId, jarDetails, c);
		} finally {
			if (c != null) {
				c.close();
			}
		}
	}

	private static void persistJar(long fileId,
			JarVerificationDetails jarDetails, Connection c)
			throws SQLException {
		PreparedStatement insertJar = null;
		try {

			insertJar = c
					.prepareStatement("INSERT INTO JAR (ID, SIGNED, ALL_ENTRIES_SIGNED, SEALED) VALUES (?,?,?,?)");
			insertJar.setLong(1, fileId);
			insertJar.setBoolean(2, jarDetails.signed);
			insertJar.setBoolean(3, jarDetails.allEntriesSigned);
			insertJar.setBoolean(4, jarDetails.sealedPackages != null);
			insertJar.execute();
		} finally {
			if (insertJar != null) {
				insertJar.close();
			}
		}
	}

	private static void persistSealedPackages(long fileId,
			JarVerificationDetails jarDetails, Connection c)
			throws SQLException {
		PreparedStatement insertSealedPackage = null;
		try {
			insertSealedPackage = c
					.prepareStatement("INSERT INTO JAR_SEALED_PACKAGES (FILE_ID, PACKAGE) VALUES (?,?)");

			for (String sealedPackage : jarDetails.sealedPackages) {
				insertSealedPackage.setLong(1, fileId);
				insertSealedPackage.setString(2, sealedPackage);
				insertSealedPackage.addBatch();
			}
			insertSealedPackage.executeBatch();
		} finally {
			if (insertSealedPackage != null) {
				insertSealedPackage.close();
			}
		}
	}

	private static void persistCertPaths(long fileId,
			JarVerificationDetails jarDetails, Connection c)
			throws SQLException {
		PreparedStatement insertCertPaths = null;
		try {
			insertCertPaths = c
					.prepareStatement("INSERT INTO JAR_CERT_PATHS(FILE_ID, ALGORITHM, PRINCIPAL, FORMAT, NOT_BEFORE, NOT_AFTER, TRUSTED) VALUES (?,?,?,?,?,?,?)");
			for (CertificatePathDetails certDetails : jarDetails.certificateDetails) {
				insertCertPaths.setLong(1, fileId);
				insertCertPaths.setString(2, certDetails.algorithm);
				insertCertPaths.setString(3, certDetails.principal);
				insertCertPaths.setString(4, certDetails.format);
				insertCertPaths.setDate(5,
						new Date(certDetails.notBefore.getTime()));
				insertCertPaths.setDate(6,
						new Date(certDetails.notAfter.getTime()));
				insertCertPaths.setBoolean(7, certDetails.trusted);
				insertCertPaths.addBatch();
			}

			insertCertPaths.executeBatch();
		} finally {
			if (insertCertPaths != null) {
				insertCertPaths.close();
			}
		}
	}

	private void persistDetails(VerificationDetails verificationDetails, long id)
			throws SQLException {
		Connection c = null;
		PreparedStatement insertSignature = null;
		PreparedStatement getPublicKey = null;
		PreparedStatement insertPublicKey = null;
		PreparedStatement insertPublicKeyUser = null;
		ResultSet generatedId = null;
		try {
			c = cp.getConnection();
			c.setAutoCommit(false);

			if (verificationDetails.key.getSignatures() != null) {
				insertSignature = persistSignature(verificationDetails, c, id);
				// Check to see if the public key has already been inserted.
				getPublicKey = c
						.prepareStatement("SELECT COUNT(*) FROM PUBLIC_KEY WHERE KEY_ID = ?");
				getPublicKey.setLong(1, verificationDetails.keyId);
				ResultSet publicKey = getPublicKey.executeQuery();
				if (publicKey.first() && publicKey.getInt(1) == 0) {
					long publicKeyId = insertPublicKey(verificationDetails, c);
					@SuppressWarnings("rawtypes")
					Iterator userIdIterator = verificationDetails.key
							.getUserIDs();
					if (userIdIterator.hasNext()) {
						insertPublicKeyUser = persistPublicKeyUser(c,
								publicKeyId, insertPublicKeyUser,
								userIdIterator);
					}
				}
			}
			c.commit();
		} finally {
			if (generatedId != null) {
				generatedId.close();
			}
			if (insertSignature != null) {
				insertSignature.close();
			}
			if (getPublicKey != null) {
				getPublicKey.close();
			}
			if (insertPublicKey != null) {
				insertPublicKey.close();
			}
			if (insertPublicKeyUser != null) {
				insertPublicKeyUser.close();
			}
			c.setAutoCommit(true);
			if (c != null) {
				c.close();
			}
		}
	}

	private PreparedStatement persistSignature(
			VerificationDetails verificationDetails, Connection c, long id)
			throws SQLException {
		PreparedStatement insertSignature;
		insertSignature = c
				.prepareStatement("INSERT INTO SIGNATURE (FILE_ID, CREATE_TIME, VERIFIED, KEY_ID) VALUES (?,?,?,?)");
		insertSignature.setLong(1, id);
		insertSignature.setDate(2, new java.sql.Date(
				verificationDetails.creationDate.getTime()));
		insertSignature.setBoolean(3, verificationDetails.verified);
		insertSignature.setLong(4, verificationDetails.keyId);
		insertSignature.execute();
		return insertSignature;
	}

	private PreparedStatement persistPom(long fileId,
			MavenDetails mavenDetails, Connection c) throws SQLException {
		PreparedStatement insertPom;
		insertPom = c
				.prepareStatement("INSERT INTO MAVEN_POM (GROUP_ID, ARTIFACT_ID, VERSION, POM_VERSION, ID) VALUES (?,?,?,?,?)");
		insertPom.setString(1, mavenDetails.getGroupId());
		insertPom.setString(2, mavenDetails.getArtifactId());
		insertPom.setString(3, mavenDetails.getVersion());
		insertPom.setInt(4, mavenDetails.getPomVersion());
		insertPom.setLong(5, fileId);
		insertPom.execute();
		return insertPom;
	}

	private PreparedStatement persistDevelopers(Connection c, long pomId,
			Set<String> developerEmails) throws SQLException {
		PreparedStatement insertDevelopers;
		insertDevelopers = c
				.prepareStatement("INSERT INTO DEVELOPERS (MAVEN_POM_ID, EMAIL) VALUES (?,?)");
		for (String s : developerEmails) {
			insertDevelopers.setLong(1, pomId);
			insertDevelopers.setString(2, s);
			insertDevelopers.addBatch();
		}
		insertDevelopers.executeBatch();
		return insertDevelopers;
	}

	private long insertPublicKey(VerificationDetails verificationDetails,
			Connection c) throws SQLException {
		PreparedStatement insertPublicKey;
		insertPublicKey = c
				.prepareStatement("INSERT INTO PUBLIC_KEY (KEY_ID, CREATE_TIME, EXPIRY_TIME, REVOKED, BIT_STRENGTH, ALGORITHM) VALUES (?,?, ?, ?, ?, ?)");
		insertPublicKey.setLong(1, verificationDetails.keyId);
		insertPublicKey.setDate(2, new java.sql.Date(verificationDetails.key
				.getCreationTime().getTime()));
		long expiryDate = verificationDetails.key.getCreationTime().getTime()
				+ verificationDetails.key.getValidSeconds() * 1000;
		insertPublicKey.setDate(3, new java.sql.Date(expiryDate));
		insertPublicKey.setBoolean(4, verificationDetails.key.isRevoked());
		insertPublicKey.setInt(5, verificationDetails.key.getBitStrength());
		String algorithm;
		switch (verificationDetails.key.getAlgorithm()) {
		case PGPPublicKey.DIFFIE_HELLMAN:
			algorithm = "DIFFIE";
			break;
		case PGPPublicKey.DSA:
			algorithm = "DSA";
			break;
		case PGPPublicKey.EC:
			algorithm = "EC";
			break;
		case PGPPublicKey.ECDSA:
			algorithm = "ECDSA";
			break;
		case PGPPublicKey.ELGAMAL_GENERAL:
			algorithm = "ELGAMAL_G";
			break;
		case PGPPublicKey.RSA_SIGN:
			algorithm = "RSA_SIGN";
			break;
		case PGPPublicKey.RSA_GENERAL:
			algorithm = "RSA_GEN";
			break;
		default:
			algorithm = "UNKNOWN";
			break;
		}
		insertPublicKey.setString(6, algorithm);
		insertPublicKey.execute();
		ResultSet publicKeyId = insertPublicKey.getGeneratedKeys();
		if (publicKeyId.first()) {
			return publicKeyId.getLong(1);
		} else {
			throw new SQLException("Can't get the generated ID.");
		}
	}

	private PreparedStatement persistPublicKeyUser(Connection c, long keyId,
			PreparedStatement insertPublicKeyUser, Iterator userIdIterator)
			throws SQLException {
		insertPublicKeyUser = c
				.prepareStatement("INSERT INTO PUBLIC_KEY_USER (PUBLIC_KEY_ID, UID) VALUES (?,?)");
		while (userIdIterator.hasNext()) {
			insertPublicKeyUser.setLong(1, keyId);
			insertPublicKeyUser.setString(2, userIdIterator.next().toString());
			insertPublicKeyUser.addBatch();
		}
		insertPublicKeyUser.executeBatch();
		return insertPublicKeyUser;
	}

	private void persistError(File file, Throwable t) {
		Connection c = null;
		PreparedStatement insertFile = null;
		try {
			c = cp.getConnection();
			String filePath = file.getAbsolutePath().substring(path.length());
			insertFile = persistError(filePath, t, c);
		} catch (SQLException e) {
			throw new RuntimeException("Problem persisting an error.", e);
		} finally {
			try {
				if (insertFile != null) {
					insertFile.close();
				}
				if (c != null) {
					c.close();
				}
			} catch (SQLException e) {
				throw new RuntimeException("Problem persisting an error.", e);
			}
		}
	}

	private PreparedStatement persistError(String filePath, Throwable t,
			Connection c) throws SQLException {
		StringWriter errorStringWriter = new StringWriter();
		t.printStackTrace(new PrintWriter(errorStringWriter));
		PreparedStatement insertPom;
		insertPom = c
				.prepareStatement("INSERT INTO ERRORS(FILE_PATH, MESSAGE, STACK_TRACE) VALUES (?,?,?)");
		insertPom.setString(1, filePath);
		insertPom.setString(2, t.getMessage());
		insertPom.setString(3, errorStringWriter.toString());
		insertPom.execute();
		return insertPom;
	}

	// http://jaredrobinson.com/blog/pitfalls-of-verifying-signed-jar-files/
}
