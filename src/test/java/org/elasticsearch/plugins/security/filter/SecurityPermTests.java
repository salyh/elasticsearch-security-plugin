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
				this.loadFile("test_default.json"));
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("8.8.8.8")) == PermLevel.ALL);
	}

	public void testNormalCases() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				this.loadFile("test_normal.json"));
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("8.8.8.9")) == PermLevel.ALL);
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("8.8.8.8")) == PermLevel.READWRITE);
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("127.0.01")) == PermLevel.READONLY);
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("1.2.3.4")) == PermLevel.NONE);
	}

	public void testNormalIndicesCases() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				this.loadFile("test_normal_indices.json"));
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("8.8.8.9")) == PermLevel.ALL);
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("8.8.8.8")) == PermLevel.READWRITE);
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("127.0.01")) == PermLevel.ALL);
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("1.2.3.4")) == PermLevel.NONE);
	}

	public void testWildcardIndicesCases() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				this.loadFile("test_wildcard_indices.json"));

		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("8.8.8.9")) == PermLevel.ALL);
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("8.8.8.8")) == PermLevel.READWRITE);
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("127.0.01")) == PermLevel.ALL);
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("1.2.3.4")) == PermLevel.NONE);
	}

	public void testWildcardMultipleIndicesCases() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex3");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				this.loadFile("test_multiple_wildcard_indices.json"));

		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("8.8.8.9")) == PermLevel.NONE);
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("8.8.8.8")) == PermLevel.READWRITE);
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("127.0.01")) == PermLevel.NONE);

		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("1.2.3.4")) == PermLevel.ALL);
	}

	public void testWildcardCases() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				this.loadFile("test_wildcard.json"));
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("8.9.8.9")) == PermLevel.ALL);
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("8.9.12.8")) == PermLevel.READWRITE);
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("127.4.0.1")) == PermLevel.READONLY);
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("103.2.3.4")) == PermLevel.NONE);
	}

	public void testNormalCasesFQHN() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				this.loadFile("test_normal_fqn.json"));
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("8.8.8.8")) == PermLevel.NONE);
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("google-public-dns-a.google.com")) == PermLevel.NONE);

	}

	public void testWildcardCasesFQHN() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				this.loadFile("test_wildcard_fqn.json"));
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("8.8.8.8")) == PermLevel.NONE);
		assertTrue(evaluator.evaluatePerm(indices,
				InetAddress.getByName("google-public-dns-a.google.com")) == PermLevel.NONE);

	}

	public void testBadFormat() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				this.loadFile("test_bad_format.json"));

		try {
			assertTrue(evaluator.evaluatePerm(indices,
					InetAddress.getByName("127.0.0.1")) == PermLevel.NONE);
			fail();
		} catch (final MalformedConfigurationException e) {

		}

	}

	public void testNoDefault() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				this.loadFile("test_no_default.json"));
		try {
			assertTrue(evaluator.evaluatePerm(indices,
					InetAddress.getByName("8.8.8.9")) == PermLevel.ALL);
			fail();
		} catch (final MalformedConfigurationException e) {

		}

	}

	public void testMalformedStructure() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				this.loadFile("test_malformed_structure.json"));
		try {
			assertTrue(evaluator.evaluatePerm(indices,
					InetAddress.getByName("8.8.8.9")) == PermLevel.ALL);
			fail();
		} catch (final MalformedConfigurationException e) {

		}

	}

}
