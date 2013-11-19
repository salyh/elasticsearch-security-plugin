package org.elasticsearch.plugins.security;

import static com.github.tlrx.elasticsearch.test.EsSetup.createIndex;
import static com.github.tlrx.elasticsearch.test.EsSetup.deleteAll;
import io.searchbox.client.JestClient;
import io.searchbox.client.JestClientFactory;
import io.searchbox.client.JestResult;
import io.searchbox.client.config.ClientConfig;
import io.searchbox.core.Index;
import io.searchbox.core.Search;

import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.io.IOUtils;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.ImmutableSettings.Builder;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import com.github.tlrx.elasticsearch.test.EsSetup;

public abstract class AbstractUnitTest {

	private final JestClientFactory factory;
	protected JestClient client;
	protected final Builder settingsBuilder;

	protected AbstractUnitTest() {
		super();

		final ClientConfig clientConfig = new ClientConfig.Builder(this.uri)
				.multiThreaded(true).build();

		// Construct a new Jest client according to configuration via factory
		this.factory = new JestClientFactory();
		this.factory.setClientConfig(clientConfig);

		this.settingsBuilder = ImmutableSettings
				.settingsBuilder()
				// .put(NODE_NAME, elasticsearchNode.name())
				// .put("node.data", elasticsearchNode.data())
				// .put("cluster.name", elasticsearchNode.clusterName())
				.put("index.store.type", "memory")
				.put("index.store.fs.memory.enabled", "true")
				.put("gateway.type", "none")
				.put("path.data", "target/data")
				.put("path.work", "target/work")
				.put("path.logs", "target/logs")
				.put("path.conf", "target/config")
				.put("path.plugins", "target/plugins")
				.put("index.number_of_shards", "1")
				.put("index.number_of_replicas", "0")
				.put(this.getProperties())
				.put("http.type",
						"org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerTransportModule");

	}

	protected Properties getProperties() {
		return new Properties();
	}

	protected final ESLogger log = Loggers.getLogger(this.getClass());

	protected final String uri = "http://localhost:8080";

	protected String loadFile(final String file) throws IOException {

		final StringWriter sw = new StringWriter();
		IOUtils.copy(this.getClass().getResourceAsStream("/" + file), sw);
		return sw.toString();

	}

	EsSetup esSetup;

	@Before
	public void setUp() throws Exception {

		// Instantiates a local node & client

		this.esSetup = new EsSetup(this.settingsBuilder.build());

		// Clean all, and creates some indices

		this.esSetup.execute(

		deleteAll(),

		createIndex("my_index_1")/*
								 * ,
								 * 
								 * createIndex("my_index_2")
								 * 
								 * .withSettings(fromClassPath(
								 * "path/to/settings.json"))
								 * 
								 * .withMapping("type1",
								 * fromClassPath("path/to/mapping/of/type1.json"
								 * ))
								 * 
								 * .withData(fromClassPath("path/to/bulk.json"))
								 */

		);

		this.client = this.factory.getObject();
	}

	@After
	public void tearDown() throws Exception {

		// This will stop and clean the local node

		this.esSetup.terminate();
		this.client.shutdownClient();

	}

	protected Map<String, Object> getHeaderMap() {
		return new HashMap<String, Object>();
	}

	protected JestResult executeIndex(final String file, final String index,
			final String type, final String id, final boolean mustBeSuccesfull)
			throws Exception {
		final JestResult res = this.client.execute(new Index.Builder(this
				.loadFile(file)).index(index).type(type).id(id).refresh(true)
				.setHeader(this.getHeaderMap()).build());

		this.log.debug("Index operation result: " + res.getJsonString());
		if (mustBeSuccesfull) {
			Assert.assertTrue(res.isSucceeded());
		}
		return res;
	}

	protected JestResult executeSearch(final String file,
			final boolean mustBeSuccesfull) throws Exception {

		final JestResult res = this.client.execute(new Search.Builder(this
				.loadFile(file)).refresh(true).setHeader(this.getHeaderMap())
				.build());

		this.log.debug("Search operation result: " + res.getJsonString());
		if (mustBeSuccesfull) {
			Assert.assertTrue(res.isSucceeded());
		}
		return res;
	}
}
