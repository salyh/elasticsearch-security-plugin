package org.elasticsearch.plugins.security.filter;

import java.io.IOException;
import java.io.StringWriter;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.commons.io.IOUtils;
import org.elasticsearch.plugins.security.MalformedConfigurationException;
import org.elasticsearch.plugins.security.service.permission.PermEvaluator;
import org.elasticsearch.plugins.security.service.permission.UserRoleCallback;

/**
 * Unit test for simple App.
 */
public class SecurityPermTests extends TestCase {

	/**
	 * Create the test case
	 * 
	 * @param testName
	 *            name of the test case
	 */
	public SecurityPermTests(final String testName) {
		super(testName);

	}

	/**
	 * @return the suite of tests being tested
	 */
	public static Test suite() {
		return new TestSuite(SecurityPermTests.class);
	}

	public void testEmptyConfigException() {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");

		try {
			new PermLevelEvaluator(null);
			fail();
		} catch (final Exception e) {
			// expected
		}

	}

	private String loadFile(final String file) throws IOException {

		final StringWriter sw = new StringWriter();
		IOUtils.copy(this.getClass().getResourceAsStream("/" + file), sw);
		return sw.toString();

	}

	public void testDefault() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");
		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				loadFile("test_default.json"));
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("8.8.8.8"), null) == PermLevel.ALL);
	}

	public void testNormalCases() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				loadFile("test_normal.json"));
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("8.8.8.9"), null) == PermLevel.ALL);
		
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("8.8.8.8"), null) == PermLevel.READWRITE);
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("127.0.01"), null) == PermLevel.READONLY);
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("1.2.3.4"), null) == PermLevel.NONE);
	}

	public void testNormalCasesWithUserRoleTypes() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");

		final List<String> types = new ArrayList<String>();
		types.add("secrettype");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				loadFile("test_normal_withuserroletypes.json"));
		assertTrue(evaluator.evaluatePerm(indices, types, InetAddress
				.getByName("127.0.01"), new TestCallback("mister", "unknown")) == PermLevel.READONLY);

		assertTrue(evaluator.evaluatePerm(indices, types, InetAddress
				.getByName("127.0.01"), new TestCallback("kirk", "unknown")) == PermLevel.READWRITE);

		assertTrue(evaluator.evaluatePerm(indices, types, InetAddress
				.getByName("8.8.8.8"), new TestCallback("kirk", "unknown")) == PermLevel.ALL);

	}

	public void testNormalIndicesCases() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				loadFile("test_normal_indices.json"));
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("8.8.8.9"), null) == PermLevel.ALL);
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("8.8.8.8"), null) == PermLevel.READWRITE);
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("128.0.0.1"), null) == PermLevel.ALL);
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("1.2.3.4"), null) == PermLevel.NONE);
	}

	public void testWildcardIndicesCases() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				loadFile("test_wildcard_indices.json"));

		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("8.8.8.9"), null) == PermLevel.ALL);
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("8.8.8.8"), null) == PermLevel.READWRITE);
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("128.0.0.1"), null) == PermLevel.ALL);
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("1.2.3.4"), null) == PermLevel.NONE);
	}

	public void testWildcardMultipleIndicesCases() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex3");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				loadFile("test_multiple_wildcard_indices.json"));

		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("8.8.8.9"), null) == PermLevel.NONE);
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("8.8.8.8"), null) == PermLevel.READWRITE);
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("127.1.0.1"), null) == PermLevel.NONE);

		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("1.2.3.4"), null) == PermLevel.ALL);
	}
	
	public void testWildcardIndicesCases2() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex");
		indices.add("xtestindexy");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				loadFile("test_wildcard_indices2.json"));

		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("127.0.0.1"), null) == PermLevel.READWRITE);

	}
	
	public void testWildcardIndicesCases22() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex-1020");
		indices.add("testindex-9");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				loadFile("test_wildcard_indices2.json"));

		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("127.0.0.1"), null) == PermLevel.ALL);

	}

	public void testWildcardCases() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				loadFile("test_wildcard.json"));
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("8.9.8.9"), null) == PermLevel.ALL);
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("8.9.12.8"), null) == PermLevel.READWRITE);
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("127.4.0.1"), null) == PermLevel.READONLY);
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("103.2.3.4"), null) == PermLevel.NONE);
	}

	public void testNormalCasesFQHN() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				loadFile("test_normal_fqn.json"));
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("8.8.8.8"), null) == PermLevel.NONE);
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("google-public-dns-a.google.com"), null) == PermLevel.NONE);

	}

	public void testWildcardCasesFQHN() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				loadFile("test_wildcard_fqn.json"));
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("8.8.8.8"), null) == PermLevel.NONE);
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("google-public-dns-a.google.com"), null) == PermLevel.NONE);

	}

	public void testBadFormat() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				loadFile("test_bad_format.json"));

		try {
			assertTrue(evaluator.evaluatePerm(indices, null,
					InetAddress.getByName("127.0.0.1"), null) == PermLevel.NONE);
			fail();
		} catch (final MalformedConfigurationException e) {

		}

	}

	public void testNoDefault() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				loadFile("test_no_default.json"));
		try {
			assertTrue(evaluator.evaluatePerm(indices, null,
					InetAddress.getByName("8.8.8.9"), null) == PermLevel.ALL);
			fail();
		} catch (final MalformedConfigurationException e) {

		}

	}

	public void testMalformedStructure() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				loadFile("test_malformed_structure.json"));
		try {
			assertTrue(evaluator.evaluatePerm(indices, null,
					InetAddress.getByName("8.8.8.9"), null) == PermLevel.ALL);
			fail();
		} catch (final MalformedConfigurationException e) {

		}

	}

	private static class TestCallback implements UserRoleCallback {

		private final String user;
		private final String role;

		protected TestCallback(final String user, final String role) {
			super();
			this.user = user;
			this.role = role;
		}

		@Override
		public String getRemoteuser() {
			// TODO Auto-generated method stub
			return user;
		}

		@Override
		public boolean isRemoteUserInRole(final String role) {
			// TODO Auto-generated method stub
			return role.equals(this.role);
		}

	}

}
