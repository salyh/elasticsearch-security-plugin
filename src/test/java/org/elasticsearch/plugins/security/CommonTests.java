package org.elasticsearch.plugins.security;

import io.searchbox.client.JestClient;
import io.searchbox.client.JestClientFactory;
import io.searchbox.client.JestResult;
import io.searchbox.client.config.ClientConfig;
import io.searchbox.core.Index;
import io.searchbox.core.Search;

import java.io.IOException;
import java.io.StringWriter;
import java.util.Arrays;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.github.tlrx.elasticsearch.test.annotations.ElasticsearchNode;
import com.github.tlrx.elasticsearch.test.annotations.ElasticsearchSetting;
import com.github.tlrx.elasticsearch.test.support.junit.runners.ElasticsearchRunner;

@RunWith(ElasticsearchRunner.class)
@ElasticsearchNode(settings = {
		@ElasticsearchSetting(name = "index.number_of_shards", value = "1"),
		@ElasticsearchSetting(name = "index.number_of_replicas", value = "0"),
		@ElasticsearchSetting(name = "index.store.type", value = "memory"),
		@ElasticsearchSetting(name = "index.gateway.type", value = "none"),
		@ElasticsearchSetting(name = "path.data", value = "target/data"),
		@ElasticsearchSetting(name = "path.plugins", value = "target/plugins"),
		@ElasticsearchSetting(name = "path.conf", value = "target/config"),
		@ElasticsearchSetting(name = "path.logs", value = "target/log"),
		@ElasticsearchSetting(name = "http.type", value = "org.elasticsearch.plugins.security.http.netty.NettyHttpServerTransportModule")})

public class CommonTests {

	protected final ESLogger log = Loggers.getLogger(this.getClass());

	protected String loadFile(final String file) throws IOException {

		final StringWriter sw = new StringWriter();
		IOUtils.copy(this.getClass().getResourceAsStream("/" + file), sw);
		return sw.toString();

	}

	@Before
	public void before() {
		this.log.info("before()");
	}

	@Test
	public void denyAllTest() throws Exception {
		final ClientConfig clientConfig = new ClientConfig.Builder(
				"http://localhost:9200").multiThreaded(true).build();

		// Construct a new Jest client according to configuration via factory
		final JestClientFactory factory = new JestClientFactory();
		factory.setClientConfig(clientConfig);
		final JestClient client = factory.getObject();

		JestResult res = client.execute(new Index.Builder(this
				.loadFile("test_denyall.json")).index("securityconfiguration")
				.type("actionpathfilter").id("actionpathfilter").refresh(true)
				.build());

		Assert.assertTrue(res.isSucceeded());
			
		res = client.execute(new Index.Builder(this
				.loadFile("dummy_content.json")).index("twitter").type("tweet")
				.id("1").refresh(true).build());

		Assert.assertTrue(!res.isSucceeded());
		this.log.info(res.getJsonString());
	}

	@Test
	public void allowTest() throws Exception {
		final ClientConfig clientConfig = new ClientConfig.Builder(
				"http://localhost:9200").multiThreaded(true).build();

		// Construct a new Jest client according to configuration via factory
		final JestClientFactory factory = new JestClientFactory();
		factory.setClientConfig(clientConfig);
		final JestClient client = factory.getObject();

		JestResult res = client.execute(new Index.Builder(this
				.loadFile("test_normal.json")).index("securityconfiguration")
				.type("actionpathfilter").id("actionpathfilter").refresh(true)
				.build());

		Assert.assertTrue(res.isSucceeded());

		res = client.execute(new Index.Builder(this
				.loadFile("dummy_content.json")).index("twitter").type("tweet")
				.id("1").refresh(true).build());

		Assert.assertTrue(res.isSucceeded());
		this.log.info(res.getJsonString());

	}

	@Test
	public void queryDoubleFieldTest() throws Exception {
		final ClientConfig clientConfig = new ClientConfig.Builder(
				"http://localhost:9200").multiThreaded(true).build();

		// Construct a new Jest client according to configuration via factory
		final JestClientFactory factory = new JestClientFactory();
		factory.setClientConfig(clientConfig);
		final JestClient client = factory.getObject();

		JestResult res = client.execute(new Index.Builder(this
				.loadFile("test_normal.json")).index("securityconfiguration")
				.type("actionpathfilter").id("actionpathfilter").refresh(true)
				.build());

		Assert.assertTrue(res.isSucceeded());

		res = client.execute(new Index.Builder(this
				.loadFile("dummy_content.json")).index("twitter").type("tweet")
				.id("1").refresh(true).build());

		Assert.assertTrue(res.isSucceeded());

		res = client.execute(new Index.Builder(this
				.loadFile("test_fr_idonly.json"))
				.index("securityconfiguration").type("fieldresponsefilter")
				.id("fieldresponsefilter").refresh(true).build());

		Assert.assertTrue(res.isSucceeded());

		res = client.execute(new Search.Builder(this
				.loadFile("field_query.json")).refresh(true).build());

		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(!res.getJsonString().contains("user")
				&& !res.getJsonString().contains("saly"));

		res = client.execute(new Search.Builder(this
				.loadFile("non_field_query.json")).refresh(true).build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(!res.getJsonString().contains("user")
				&& !res.getJsonString().contains("saly"));

		res = client.execute(new Search.Builder(this
				.loadFile("double_field_query.json")).refresh(true).build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(!res.getJsonString().contains("user")
				&& !res.getJsonString().contains("saly"));

	}

	@Test
	public void queryNonFieldTest() throws Exception {
		final ClientConfig clientConfig = new ClientConfig.Builder(
				"http://localhost:9200").multiThreaded(true).build();

		// Construct a new Jest client according to configuration via factory
		final JestClientFactory factory = new JestClientFactory();
		factory.setClientConfig(clientConfig);
		final JestClient client = factory.getObject();

		JestResult res = client.execute(new Index.Builder(this
				.loadFile("test_normal.json")).index("securityconfiguration")
				.type("actionpathfilter").id("actionpathfilter").refresh(true)
				.build());

		Assert.assertTrue(res.isSucceeded());

		res = client.execute(new Index.Builder(this
				.loadFile("dummy_content.json")).index("twitter").type("tweet")
				.id("1").refresh(true).build());

		Assert.assertTrue(res.isSucceeded());

		res = client.execute(new Index.Builder(this
				.loadFile("test_fr_all.json")).index("securityconfiguration")
				.type("fieldresponsefilter").id("fieldresponsefilter")
				.refresh(true).build());

		Assert.assertTrue(res.isSucceeded());

		res = client.execute(new Search.Builder(this
				.loadFile("field_query.json")).refresh(true).build());

		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(res.getJsonString().contains("user")
				&& res.getJsonString().contains("saly"));

		res = client.execute(new Search.Builder(this
				.loadFile("non_field_query.json")).refresh(true).build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(res.getJsonString().contains("user")
				&& res.getJsonString().contains("saly"));

		res = client.execute(new Search.Builder(this
				.loadFile("double_field_query.json")).refresh(true).build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(res.getJsonString().contains("user")
				&& res.getJsonString().contains("saly"));

	}

	@Test
	public void queryNonFieldWhitespaceTest() throws Exception {
		final ClientConfig clientConfig = new ClientConfig.Builder(
				"http://localhost:9200").multiThreaded(true).build();

		// Construct a new Jest client according to configuration via factory
		final JestClientFactory factory = new JestClientFactory();
		factory.setClientConfig(clientConfig);
		final JestClient client = factory.getObject();

		JestResult res = client.execute(new Index.Builder(this
				.loadFile("test_normal.json")).index("securityconfiguration")
				.type("actionpathfilter").id("actionpathfilter").refresh(true)
				.build());

		Assert.assertTrue(res.isSucceeded());

		res = client.execute(new Index.Builder(this
				.loadFile("dummy_content.json")).index("twitter").type("tweet")
				.id("1").refresh(true).build());

		Assert.assertTrue(res.isSucceeded());

		res = client.execute(new Index.Builder(this
				.loadFile("test_fr_all_whitespace.json"))
				.index("securityconfiguration").type("fieldresponsefilter")
				.id("fieldresponsefilter").refresh(true).build());

		Assert.assertTrue(res.isSucceeded());

		res = client.execute(new Search.Builder(this
				.loadFile("field_query.json")).refresh(true).build());

		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(res.getJsonString().contains("user")
				&& res.getJsonString().contains("saly"));

		res = client.execute(new Search.Builder(this
				.loadFile("non_field_query.json")).refresh(true).build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(res.getJsonString().contains("user")
				&& res.getJsonString().contains("saly"));

		res = client.execute(new Search.Builder(this
				.loadFile("double_field_query.json")).refresh(true).build());
		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());
		Assert.assertTrue(res.getJsonString().contains("user")
				&& res.getJsonString().contains("saly"));

	}

	@Test
	public void queryGETUrlTest() throws Exception {
		final ClientConfig clientConfig = new ClientConfig.Builder(
				"http://localhost:9200").multiThreaded(true).build();

		// Construct a new Jest client according to configuration via factory
		final JestClientFactory factory = new JestClientFactory();
		factory.setClientConfig(clientConfig);
		final JestClient client = factory.getObject();

		JestResult res = client.execute(new Index.Builder(this
				.loadFile("test_normal.json")).index("securityconfiguration")
				.type("actionpathfilter").id("actionpathfilter").refresh(true)
				.build());

		Assert.assertTrue(res.isSucceeded());

		res = client.execute(new Index.Builder(this
				.loadFile("dummy_content.json")).index("twitter").type("tweet")
				.id("1").refresh(true).build());

		Assert.assertTrue(res.isSucceeded());

		res = client.execute(new Index.Builder(this
				.loadFile("test_fr_all_whitespace.json"))
				.index("securityconfiguration").type("fieldresponsefilter")
				.id("fieldresponsefilter").refresh(true).build());

		Assert.assertTrue(res.isSucceeded());

		final CloseableHttpClient httpclient = HttpClients.createDefault();
		final HttpGet httpGet = new HttpGet("http://localhost:9200/%5Fsearch");
		final CloseableHttpResponse response1 = httpclient.execute(httpGet);
		this.log.debug(response1.getStatusLine().getStatusCode() + "");
		final HttpEntity entity1 = response1.getEntity();
		this.log.debug(EntityUtils.toString(entity1));

	}

	@Test
	public void httptest() throws Exception {
		final CloseableHttpClient httpclient = HttpClients.createDefault();
		final HttpGet httpGet = new HttpGet(
				"http://localhost:9200/securityconfiguration/%5Fsearch");
		// spoof
		httpGet.addHeader("X-Forwarded-For", "www.google.de");
		this.log.debug("headers: " + Arrays.toString(httpGet.getAllHeaders()));
		final CloseableHttpResponse response1 = httpclient.execute(httpGet);
		this.log.debug(response1.getStatusLine().getStatusCode() + "");
		final HttpEntity entity1 = response1.getEntity();
		this.log.debug(EntityUtils.toString(entity1));

	}
}
