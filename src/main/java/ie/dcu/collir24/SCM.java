package ie.dcu.collir24;

/**
 * Maven SCM element from POM
 * 
 * @author rcollins
 * 
 */
public class SCM {
	private final String url;
	private final String connection;
	private final String developerConnection;

	public SCM(String url, String connection, String developerConnection) {
		super();
		this.url = url;
		this.connection = connection;
		this.developerConnection = developerConnection;
	}

	public String getUrl() {
		return url;
	}

	public String getConnection() {
		return connection;
	}

	public String getDeveloperConnection() {
		return developerConnection;
	}

	@Override
	public String toString() {
		return "SCM [url=" + url + ", connection=" + connection
				+ ", developerConnection=" + developerConnection + "]";
	}

}
