package org.elasticsearch.plugins.security.filter;

import java.io.IOException;
import java.io.StringWriter;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.elasticsearch.plugins.security.MalformedConfigurationException;
import org.elasticsearch.plugins.security.service.permission.PermEvaluator;
import org.elasticsearch.plugins.security.service.permission.UserRoleCallback;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import static org.junit.Assert.*;

/**
 * Unit test for simple App.
 */
public class SecurityPermTests extends AbstractPermTests{	

    @Test(expected=IllegalArgumentException.class)
	public void testEmptyConfigException() {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");
		new PermLevelEvaluator(null);			
	}

	
	@Test
	public void testDefault() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
		indices.add("testindex2");
		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				loadFile("test_default.json"));
		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("8.8.8.8"), null) == PermLevel.ALL);
	}
	@Test
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
	@Test
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
	@Test
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
	@Test
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
	@Test
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
	@Test
	public void testWildcardIndicesCases2() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex");
		indices.add("xtestindexy");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				loadFile("test_wildcard_indices2.json"));

		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("127.0.0.1"), null) == PermLevel.READWRITE);

	}
	@Test
	public void testWildcardIndicesCases22() throws Exception {

		final List<String> indices = new ArrayList<String>();
		indices.add("testindex-1020");
		indices.add("testindex-9");

		final PermEvaluator<?> evaluator = new PermLevelEvaluator(
				loadFile("test_wildcard_indices2.json"));

		assertTrue(evaluator.evaluatePerm(indices, null,
				InetAddress.getByName("127.0.0.1"), null) == PermLevel.ALL);

	}
	@Test
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
	@Test
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
	@Test
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
	@Test
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
	@Test
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
	@Test
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
	
	@Test
    public void testEmptyArrays() throws Exception {

        final PermEvaluator<?> evaluator = new PermLevelEvaluator(
                loadFile("test_denyall_emptyarray.json"));
       
        assertTrue(evaluator.evaluatePerm(null, null,
                InetAddress.getByName("8.8.8.8"), null) == PermLevel.NONE);
            

    }

}
