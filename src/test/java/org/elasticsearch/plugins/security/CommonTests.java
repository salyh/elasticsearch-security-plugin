package org.elasticsearch.plugins.security;

import io.searchbox.client.JestClient;
import io.searchbox.client.JestClientFactory;
import io.searchbox.client.JestResult;
import io.searchbox.client.config.ClientConfig;
import io.searchbox.core.Index;

import java.io.IOException;
import java.io.StringWriter;

import org.apache.commons.io.IOUtils;
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
		@ElasticsearchSetting(name = "path.logs", value = "target/log") })
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
				.type("actionpathfilter").id("actionpathfilter").build());

		Assert.assertTrue(res.isSucceeded());

		res = client.execute(new Index.Builder(this
				.loadFile("dummy_content.json")).index("twitter").type("tweet")
				.id("1").build());

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
				.type("actionpathfilter").id("actionpathfilter").build());

		Assert.assertTrue(res.isSucceeded());

		res = client.execute(new Index.Builder(this
				.loadFile("dummy_content.json")).index("twitter").type("tweet")
				.id("1").build());

		Assert.assertTrue(res.isSucceeded());
		this.log.info(res.getJsonString());

	}

}
