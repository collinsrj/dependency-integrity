package ie.dcu.collir24;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

class MavenDetails {
	private final String groupId;
	private final String artifactId;
	private final String version;
	private final int pomVersion;
	private final Set<String> developerEmails = new LinkedHashSet<String>();
	private SCM scm;

	/**
	 * Construct pom v4 details
	 * 
	 * @param groupId
	 * @param artifactId
	 * @param version
	 */
	public MavenDetails(int pomVersion, String groupId, String artifactId,
			String version) {
		super();
		this.pomVersion = pomVersion;
		this.groupId = groupId;
		this.artifactId = artifactId;
		this.version = version;
	}

	public SCM getScm() {
		return scm;
	}

	public void setScm(SCM scm) {
		this.scm = scm;
	}

	public String getGroupId() {
		return groupId;
	}

	public String getArtifactId() {
		return artifactId;
	}

	public String getVersion() {
		return version;
	}

	public int getPomVersion() {
		return pomVersion;
	}

	public Set<String> getDeveloperEmails() {
		return developerEmails;
	}

	@Override
	public String toString() {
		return "MavenDetails [groupId=" + groupId + ", artifactId="
				+ artifactId + ", version=" + version + ", pomVersion="
				+ pomVersion + ", developerEmails=" + developerEmails
				+ ", scm=" + scm + "]";
	}

}