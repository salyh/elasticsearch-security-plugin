package org.elasticsearch.plugins.security;

import io.searchbox.client.JestResult;
import io.searchbox.core.Index;
import io.searchbox.core.Search;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.junit.Assert;
import org.junit.Test;

public abstract class SpnegoTests extends AbstractUnitTest {

	@Override
	protected Properties getProperties() {

		final Properties props = new Properties();
		props.putAll(super.getProperties());
		props.setProperty("security.http.xforwardedfor.header",
				"X-Forwarded-For");
		props.setProperty("security.http.xforwardedfor.trustedproxies",
				"123.123.123.123, 111.222.111.222");
		return props;
	}

	@Override
	protected Map<String, Object> getHeaderMap() {
		final Map<String, Object> map = new HashMap<String, Object>();
		map.putAll(super.getHeaderMap());
		map.put("Authorization", "foo bar");
		return map;
	}

	// ---

	@Test
	public void common_normalTest() throws Exception {

		JestResult res = this.client.execute(new Index.Builder(this
				.loadFile("ur_test_normal.json"))
				.index("securityconfiguration").type("actionpathfilter")
				.id("actionpathfilter").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.debug(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("dummy_content.json")).index("twitter").type("tweet")
				.id("1").refresh(true).setHeader("Authorization", "foo bar")
				.build());

		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

	}

	@Test
	public void common_dupTest() throws Exception {

		JestResult res = this.client.execute(new Index.Builder(this
				.loadFile("ur_test_duplicate.json"))
				.index("securityconfiguration").type("actionpathfilter")
				.id("actionpathfilter").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.debug(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("dummy_content.json")).index("twitter").type("tweet")
				.id("1").refresh(true).setHeader("Authorization", "foo bar")
				.build());

		this.log.info(res.getJsonString());
		Assert.assertTrue(!res.isSucceeded());

	}

	// --

	@Test
	public void singleHeaderTest() throws Exception {

		JestResult res = this.client.execute(new Index.Builder(this
				.loadFile("test_normal.json")).index("securityconfiguration")
				.type("actionpathfilter").id("actionpathfilter").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.debug(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("dls_default_test_allowall.json"))
				.index("securityconfiguration").type("dlspermissions")
				.id("default").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.debug(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("fls_test_normal.json"))
				.index("securityconfiguration").type("dlspermissions")
				.id("dlspermissions").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.debug(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		/*
		 * res = client.execute(new Index.Builder(this
		 * .loadFile("test_fr_idonly.json"))
		 * .index("securityconfiguration").type("fieldresponsefilter");()m
		 * .id("fieldresponsefilter").refresh(true).build());
		 */

		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Search.Builder(this
				.loadFile("non_field_query.json")).refresh(true)
				.setHeader("X-Forwarded-For", "3.1.55.2").build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

	}

	@Test
	public void badProxiesTest() throws Exception {

		this.executeIndex("dls_default_test_allowall.json",
				"securityconfiguration", "dlspermissions", "default", true);

		this.executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);

		JestResult res = this.client.execute(new Index.Builder(this
				.loadFile("test_normal.json")).index("securityconfiguration")
				.type("actionpathfilter").id("actionpathfilter").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.debug(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		/*
		 * res = client.execute(new Index.Builder(this
		 * .loadFile("test_fr_idonly.json"))
		 * .index("securityconfiguration").type("fieldresponsefilter");()m
		 * .id("fieldresponsefilter").refresh(true) .setHeader("Authorization",
		 * "foo bar").build());
		 * 
		 * Assert.assertTrue(res.isSucceeded());
		 */

		res = this.client.execute(new Search.Builder(this
				.loadFile("non_field_query.json"))
				.refresh(true)
				.setHeader("Authorization", "foo bar")
				.setHeader("X-Forwarded-For",
						"3.1.55.2, 123.12.123.123, 111.222.111.222").build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(!res.isSucceeded());

	}

	@Test
	public void goodProxiesTest() throws Exception {

		this.executeIndex("dls_default_test_allowall.json",
				"securityconfiguration", "dlspermissions", "default", true);

		this.executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);

		JestResult res = this.client.execute(new Index.Builder(this
				.loadFile("test_normal.json")).index("securityconfiguration")
				.type("actionpathfilter").id("actionpathfilter").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.debug(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		/*
		 * res = client.execute(new Index.Builder(this
		 * .loadFile("test_fr_idonly.json"))
		 * .index("securityconfiguration").type("fieldresponsefilter");()m
		 * .id("fieldresponsefilter").refresh(true) .setHeader("Authorization",
		 * "foo bar").build());
		 * 
		 * Assert.assertTrue(res.isSucceeded());
		 */

		res = this.client.execute(new Search.Builder(this
				.loadFile("non_field_query.json"))
				.refresh(true)
				.setHeader("Authorization", "foo bar")
				.setHeader("X-Forwarded-For",
						"3.1.55.2, 123.123.123.123, 111.222.111.222").build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

	}

	@Test
	public void goodProxiesTestSingle() throws Exception {

		this.executeIndex("dls_default_test_allowall.json",
				"securityconfiguration", "dlspermissions", "default", true);

		this.executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);

		JestResult res = this.client.execute(new Index.Builder(this
				.loadFile("test_normal.json")).index("securityconfiguration")
				.type("actionpathfilter").id("actionpathfilter").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.debug(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		/*
		 * 
		 * res = client.execute(new Index.Builder(this
		 * .loadFile("test_fr_idonly.json"))
		 * .index("securityconfiguration").type("fieldresponsefilter");()m
		 * .id("fieldresponsefilter").refresh(true) .setHeader("Authorization",
		 * "foo bar").build());
		 */

		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Search.Builder(this
				.loadFile("non_field_query.json")).refresh(true)
				.setHeader("X-Forwarded-For", "3.1.55.2, 123.123.123.123")
				.build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

	}

	public void queryDoubleFieldTest1() throws Exception {

		this.executeIndex("dls_default_test_allowall.json",
				"securityconfiguration", "dlspermissions", "default", true);

		this.executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);

		JestResult res = this.client.execute(new Index.Builder(this
				.loadFile("test_normal.json")).index("securityconfiguration")
				.type("actionpathfilter").id("actionpathfilter").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.debug(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("dummy_content.json")).index("twitter").type("tweet")
				.id("1").refresh(true).setHeader("Authorization", "foo bar")
				.build());

		Assert.assertTrue(res.isSucceeded());

		/*
		 * res = client.execute(new Index.Builder(this
		 * .loadFile("test_fr_idonly.json"))
		 * .index("securityconfiguration").type("fieldresponsefilter");()m
		 * .id("fieldresponsefilter").refresh(true).build());
		 * 
		 * Assert.assertTrue(res.isSucceeded());
		 */

		res = this.client.execute(new Search.Builder(this
				.loadFile("field_query.json")).refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(!res.getJsonString().contains("user")
				&& !res.getJsonString().contains("saly"));

		res = this.client.execute(new Search.Builder(this
				.loadFile("non_field_query.json")).refresh(true)
				.setHeader("Authorization", "foo bar").build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(!res.getJsonString().contains("user")
				&& !res.getJsonString().contains("saly"));

		res = this.client.execute(new Search.Builder(this
				.loadFile("double_field_query.json"))
				.refresh(true)
				.setHeader("Authorization", "foo bar")
				.setHeader("X-Forwarded-For",
						"3.1.55.2, 123.123.123.123, 111.222.111.222").build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(!res.getJsonString().contains("user")
				&& !res.getJsonString().contains("saly"));

	}

	// --
	@Test
	public void normalTest2() throws Exception {

		this.executeIndex("dls_default_test_denyall.json",
				"securityconfiguration", "dlspermissions", "default", true);
		this.executeIndex("ur_test_normal.json", "securityconfiguration",
				"actionpathfilter", "actionpathfilter", true);
		this.executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);
		this.executeIndex("fls_dummy_content.json", "twitter", "tweet", "1",
				true);
		this.executeIndex("dls_dummy_content_without_dls.json", "twitter",
				"tweet", "2", true);
		this.executeSearch("fls_field_query.json", true);

	}

	public void normalTest22() throws Exception {

		JestResult res = this.client.execute(new Index.Builder(this
				.loadFile("ur_test_normal.json"))
				.index("securityconfiguration").type("actionpathfilter")
				.id("actionpathfilter").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.debug(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("fls_test_normal.json"))
				.index("securityconfiguration").type("dlspermissions")
				.id("dlspermissions").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.debug(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("fls_dummy_content.json")).index("twitter")
				.type("tweet").id("1").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Search.Builder(this
				.loadFile("fls_field_query.json")).refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.info(res.getJsonString());
		this.log.info(res.getJsonString());

	}

	// --
	// dls

	@Test
	public void normalTest() throws Exception {

		JestResult res = this.client.execute(new Index.Builder(this
				.loadFile("ur_test_normal.json"))
				.index("securityconfiguration").type("actionpathfilter")
				.id("actionpathfilter").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.debug(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("fls_test_normal.json"))
				.index("securityconfiguration").type("dlspermissions")
				.id("dlspermissions").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.debug(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("fls_dummy_content.json")).index("twitter")
				.type("tweet").id("1").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("fls_dummy_content_updt.json")).index("twitter")
				.type("tweet").id("1").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Search.Builder(this
				.loadFile("fls_field_query.json")).refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.info(res.getJsonString());
		this.log.info(res.getJsonString());

	}

	@Test
	public void normalTest23() throws Exception {

		JestResult res = this.client.execute(new Index.Builder(this
				.loadFile("ur_test_normal.json"))
				.index("securityconfiguration").type("actionpathfilter")
				.id("actionpathfilter").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.debug(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("fls_test_normal.json"))
				.index("securityconfiguration").type("dlspermissions")
				.id("dlspermissions").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.debug(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("fls_dummy_content.json")).index("twitter")
				.type("tweet").id("1").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Search.Builder(this
				.loadFile("fls_field_query.json")).refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.info(res.getJsonString());
		this.log.info(res.getJsonString());

	}

	// --

	@Test
	public void denyAllTest() throws Exception {

		JestResult res = this.client.execute(new Index.Builder(this
				.loadFile("test_denyall.json")).index("securityconfiguration")
				.type("actionpathfilter").id("actionpathfilter").refresh(true)
				.setParameter("user.name", "dummy")
				.setHeader("Authorization", "foo bar").build());

		this.log.debug(res.getJsonString());
		this.log.debug(res.getErrorMessage());

		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("dummy_content.json")).index("twitter").type("tweet")
				.id("1").refresh(true).setParameter("user.name", "dummy")
				.setHeader("Authorization", "foo bar").build());

		Assert.assertTrue(!res.isSucceeded());
		this.log.info(res.getJsonString());

	}

	@Test
	public void allowTest() throws Exception {

		JestResult res = this.client.execute(new Index.Builder(this
				.loadFile("test_normal.json")).index("securityconfiguration")
				.type("actionpathfilter").id("actionpathfilter").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.debug(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("dummy_content.json")).index("twitter").type("tweet")
				.id("1").refresh(true).setHeader("Authorization", "foo bar")
				.build());

		Assert.assertTrue(res.isSucceeded());
		this.log.info(res.getJsonString());

	}

	public void queryDoubleFieldTest() throws Exception {

		this.executeIndex("dls_default_test_allowall.json",
				"securityconfiguration", "dlspermissions", "default", true);

		this.executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);

		JestResult res = this.client.execute(new Index.Builder(this
				.loadFile("test_normal.json")).index("securityconfiguration")
				.type("actionpathfilter").id("actionpathfilter").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("dummy_content.json")).index("twitter").type("tweet")
				.id("1").refresh(true).setHeader("Authorization", "foo bar")
				.build());

		Assert.assertTrue(res.isSucceeded());

		/*
		 * res = client.execute(new Index.Builder(this
		 * .loadFile("test_fr_idonly.json"))
		 * .index("securityconfiguration").type("fieldresponsefilter");()m
		 * .id("fieldresponsefilter").refresh(true) .setHeader("Authorization",
		 * "foo bar").build());
		 * 
		 * Assert.assertTrue(res.isSucceeded());
		 */

		res = this.client.execute(new Search.Builder(this
				.loadFile("field_query.json")).refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(!res.getJsonString().contains("user")
				&& !res.getJsonString().contains("saly"));

		res = this.client.execute(new Search.Builder(this
				.loadFile("non_field_query.json")).refresh(true)
				.setHeader("Authorization", "foo bar").build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(!res.getJsonString().contains("user")
				&& !res.getJsonString().contains("saly"));

		res = this.client.execute(new Search.Builder(this
				.loadFile("double_field_query.json")).refresh(true)
				.setHeader("Authorization", "foo bar").build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(!res.getJsonString().contains("user")
				&& !res.getJsonString().contains("saly"));

	}

	public void queryNonFieldTest() throws Exception {

		this.executeIndex("dls_default_test_allowall.json",
				"securityconfiguration", "dlspermissions", "default", true);

		this.executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);
		JestResult res = this.client.execute(new Index.Builder(this
				.loadFile("test_normal.json")).index("securityconfiguration")
				.type("actionpathfilter").id("actionpathfilter").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("dummy_content.json")).index("twitter").type("tweet")
				.id("1").refresh(true).setHeader("Authorization", "foo bar")
				.build());

		Assert.assertTrue(res.isSucceeded());

		/*
		 * res = client.execute(new Index.Builder(this
		 * .loadFile("test_fr_all.json")).index("securityconfiguration")
		 * .type("fieldresponsefilter");()m.id("fieldresponsefilter")
		 * .refresh(true).setHeader("Authorization", "foo bar").build());
		 * 
		 * Assert.assertTrue(res.isSucceeded());
		 */

		res = this.client.execute(new Search.Builder(this
				.loadFile("field_query.json")).refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(res.getJsonString().contains("user")
				&& res.getJsonString().contains("saly"));

		res = this.client.execute(new Search.Builder(this
				.loadFile("non_field_query.json")).refresh(true)
				.setHeader("Authorization", "foo bar").build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(res.getJsonString().contains("user")
				&& res.getJsonString().contains("saly"));

		res = this.client.execute(new Search.Builder(this
				.loadFile("double_field_query.json")).refresh(true)
				.setHeader("Authorization", "foo bar").build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(res.getJsonString().contains("user")
				&& res.getJsonString().contains("saly"));

	}

	public void queryNonFieldWhitespaceTest() throws Exception {

		this.executeIndex("dls_default_test_allowall.json",
				"securityconfiguration", "dlspermissions", "default", true);

		this.executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);

		JestResult res = this.client.execute(new Index.Builder(this
				.loadFile("test_normal.json")).index("securityconfiguration")
				.type("actionpathfilter").id("actionpathfilter").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("dummy_content.json")).index("twitter").type("tweet")
				.id("1").refresh(true).setHeader("Authorization", "foo bar")
				.build());

		Assert.assertTrue(res.isSucceeded());

		/*
		 * res = client.execute(new Index.Builder(this
		 * .loadFile("test_fr_all_whitespace.json"))
		 * .index("securityconfiguration").type("fieldresponsefilter");()m
		 * .id("fieldresponsefilter") .setHeader("Authorization",
		 * "foo bar").refresh(true).build());
		 */

		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Search.Builder(this
				.loadFile("field_query.json")).refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(res.getJsonString().contains("user")
				&& res.getJsonString().contains("saly"));

		res = this.client.execute(new Search.Builder(this
				.loadFile("non_field_query.json")).refresh(true)
				.setHeader("Authorization", "foo bar").build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(res.getJsonString().contains("user")
				&& res.getJsonString().contains("saly"));

		res = this.client.execute(new Search.Builder(this
				.loadFile("double_field_query.json")).refresh(true)
				.setHeader("Authorization", "foo bar").build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(res.getJsonString().contains("user")
				&& res.getJsonString().contains("saly"));

	}

	@Test
	public void queryGETUrlTest() throws Exception {

		this.executeIndex("dls_default_test_allowall.json",
				"securityconfiguration", "dlspermissions", "default", true);

		this.executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);

		JestResult res = this.client.execute(new Index.Builder(this
				.loadFile("test_normal.json")).index("securityconfiguration")
				.type("actionpathfilter").id("actionpathfilter").refresh(true)
				.setHeader("Authorization", "foo bar").build());

		Assert.assertTrue(res.isSucceeded());

		res = this.client.execute(new Index.Builder(this
				.loadFile("dummy_content.json")).index("twitter").type("tweet")
				.id("1").refresh(true).setHeader("Authorization", "foo bar")
				.build());

		Assert.assertTrue(res.isSucceeded());

		/*
		 * res = client.execute(new Index.Builder(this
		 * .loadFile("test_fr_all_whitespace.json"))
		 * .index("securityconfiguration").type("fieldresponsefilter");()m
		 * .id("fieldresponsefilter").refresh(true) .setHeader("Authorization",
		 * "foo bar").build());
		 */

		Assert.assertTrue(res.isSucceeded());

		final CloseableHttpClient httpclient = HttpClients.createDefault();
		final HttpGet httpGet = new HttpGet(this.uri + "/%5Fsearch");
		final CloseableHttpResponse response1 = httpclient.execute(httpGet);
		this.log.debug(response1.getStatusLine().getStatusCode() + "");
		final HttpEntity entity1 = response1.getEntity();
		this.log.debug(EntityUtils.toString(entity1));

	}

	@Test
	public void httptest() throws Exception {
		final CloseableHttpClient httpclient = HttpClients.createDefault();
		final HttpGet httpGet = new HttpGet(this.uri
				+ "/securityconfiguration/%5Fsearch");
		// spoof
		httpGet.addHeader("X-Forwarded-For", "www.google.de");
		this.log.debug("headers: " + Arrays.toString(httpGet.getAllHeaders()));
		final CloseableHttpResponse response1 = httpclient.execute(httpGet);
		this.log.debug(response1.getStatusLine().getStatusCode() + "");
		final HttpEntity entity1 = response1.getEntity();
		this.log.debug(EntityUtils.toString(entity1));

	}
}
