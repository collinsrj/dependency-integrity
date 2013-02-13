import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import ie.dcu.collir24.SignedFilenameFilter;

import java.io.File;

import org.junit.Test;

public class SignedFilenameFilterTest {
	@Test
	public void testMatchJar() throws Exception {
		SignedFilenameFilter filter = new SignedFilenameFilter();
		assertTrue(filter.accept(new File(""), "ant-optional-1.5.1.jar"));
	}

	@Test
	public void testBadExtension() throws Exception {
		SignedFilenameFilter filter = new SignedFilenameFilter();
		assertFalse(filter.accept(new File(""), "ant-optional-1.5.1.zzz"));
	}

	@Test
	public void testNotFile() throws Exception {
		SignedFilenameFilter filter = new SignedFilenameFilter();
		assertFalse(filter.accept(new File(""), "ant-optional-1.5.1"));
	}
}
