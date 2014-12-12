package org.elasticsearch.plugins.security;

import static com.github.tlrx.elasticsearch.test.EsSetup.createIndex;
import static com.github.tlrx.elasticsearch.test.EsSetup.deleteAll;
import io.searchbox.client.JestClient;
import io.searchbox.client.JestClientFactory;
import io.searchbox.client.JestResult;
import io.searchbox.client.config.HttpClientConfig;
import io.searchbox.client.http.JestHttpClient;
import io.searchbox.core.Get;
import io.searchbox.core.Index;
import io.searchbox.core.Search;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.net.ssl.SSLContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginContext;

import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.ImmutableSettings.Builder;
import org.elasticsearch.plugins.security.util.SecurityUtil;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.github.tlrx.elasticsearch.test.EsSetup;

public abstract class AbstractUnitTest {

	@Rule 
	public TestName name = new TestName();
	private JestClient client;
	protected final Builder settingsBuilder;
	protected Map<String, Object> headers = new HashMap<String, Object>();

	
	@Rule
    public TestWatcher testWatcher = new TestWatcher() {
        @Override
        protected void starting(final Description description) {
            String methodName = description.getMethodName();
            String className = description.getClassName();
            className = className.substring(className.lastIndexOf('.') + 1);
            System.out.println("Starting JUnit-test: " + className + " " + methodName);
        }
    };
	
	protected AbstractUnitTest() {
		super();



		settingsBuilder = ImmutableSettings
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
				.put(getProperties())
				.put("http.type",
						"org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerTransport");

	}

	protected Properties getProperties() {
		return new Properties();
	}

	protected final ESLogger log = Loggers.getLogger(this.getClass());


	protected String getServerUri() {
		return "http"+(isSSL()?"s":"")+"://localhost:8080";
	}

	protected boolean isSSL() {
		return false;
	}

	protected String loadFile(final String file) throws IOException {

		final StringWriter sw = new StringWriter();
		IOUtils.copy(this.getClass().getResourceAsStream("/" + file), sw);
		return sw.toString();

	}

	EsSetup esSetup;

	@Before
	public void setUp() throws Exception {

		headers.clear();

		// Instantiates a local node & client

		esSetup = new EsSetup(settingsBuilder.build());

		// Clean all, and creates some indices

		esSetup.execute(

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


	}

	@After
	public void tearDown() throws Exception {

		// This will stop and clean the local node

		if(esSetup != null) {
			esSetup.terminate();
		}

		if(client != null) {
			client.shutdownClient();
		}

	}



	protected JestResult executeIndex(final String file, final String index,
			final String type, final String id, final boolean mustBeSuccesfull)
					throws Exception {

		final String [] userpass = getUserPass();

		client = getJestClient(getServerUri(),userpass[0],userpass[1]);


		final JestResult res = client.execute(new Index.Builder(loadFile(file)).index(index).type(type).id(id).refresh(true)
				.setHeader(headers).build());

		log.debug("Index operation result: " + res.getJsonString());
		if (mustBeSuccesfull) {
			Assert.assertTrue(res.isSucceeded());
		} else {
			Assert.assertTrue(!res.isSucceeded());
		}

		return res;
	}



	protected JestResult executeSearch(final String file,
			final boolean mustBeSuccesfull) throws Exception {

		final String [] userpass = getUserPass();

		client = getJestClient(getServerUri(),userpass[0],userpass[1]);


		final JestResult res = client.execute(new Search.Builder(loadFile(file)).refresh(true).setHeader(headers)
				.build());

		log.debug("Search operation result: " + res.getJsonString());
		if (mustBeSuccesfull) {
			Assert.assertTrue(res.isSucceeded());
		} else {
			Assert.assertTrue(!res.isSucceeded());
		}
		return res;
	}

	protected JestResult executeGet(final String index, final String id,
			final boolean mustBeSuccesfull) throws Exception {

		final String [] userpass = getUserPass();

		client = getJestClient(getServerUri(),userpass[0],userpass[1]);


		final JestResult res = client.execute(new Get.Builder(index, id).refresh(true).setHeader(headers)
				.build());

		log.debug("Search operation result: " + res.getJsonString());
		if (mustBeSuccesfull) {
			Assert.assertTrue(res.isSucceeded());
		} else {
			Assert.assertTrue(!res.isSucceeded());
		}
		return res;
	}

	protected String [] getUserPass()
	{
		return new String[]{null,null};
	}

	/*private JestHttpClient getJestClient(String serverUri) throws Exception
	{
		return getJestClient(serverUri, null, null);
	}*/


	private JestHttpClient getJestClient(String serverUri, final String username,
			final String password) throws Exception {// http://hc.apache.org/httpcomponents-client-ga/tutorial/html/authentication.html
		final HttpClientConfig clientConfig1 = new HttpClientConfig.Builder(serverUri)
		.multiThreaded(true).build();

		// Construct a new Jest client according to configuration via factory
		final JestClientFactory factory1 = new JestClientFactory();

		factory1.setHttpClientConfig(clientConfig1);

		final JestHttpClient c = (JestHttpClient) factory1.getObject();

		final HttpClientBuilder hcb = HttpClients.custom();

		if (serverUri.startsWith("https")) {

			log.info("Configure Jest with SSL");

			final KeyStore myTrustStore = KeyStore.getInstance("PKCS12");
			myTrustStore
			.load(new FileInputStream(
					SecurityUtil
					.getAbsoluteFilePathFromClassPath("localhost_tc.p12")),
					"changeit".toCharArray());

			final KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(
					new FileInputStream(
							SecurityUtil
							.getAbsoluteFilePathFromClassPath("hnelsonclient.p12")),
							"changeit".toCharArray());

			final SSLContext sslContext = SSLContexts.custom().useTLS()
					.loadKeyMaterial(keyStore, "changeit".toCharArray())
					.loadTrustMaterial(myTrustStore)

					.build();

			final SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
					sslContext);

			hcb.setSSLSocketFactory(sslsf);

		}

		if (username != null) {

			final GSSContext context =	initGSS(new URL(serverUri), "spnego-client", username,password);
			final byte[] data = context.initSecContext(new byte[0], 0, 0);

			final List<Header> dh = new ArrayList<Header>();
			dh.add(new BasicHeader("Authorization","Negotiate "
					+ org.apache.tomcat.util.codec.binary.Base64
					.encodeBase64String(data)));

			hcb.setDefaultHeaders(dh);



		}

		c.setHttpClient(hcb.build());



		return c;

	}



	private static CallbackHandler getUsernamePasswordHandler(
			final String username, final String password) {

		final CallbackHandler handler = new CallbackHandler() {
			@Override
			public void handle(final Callback[] callback) {
				for (int i = 0; i < callback.length; i++) {
					if (callback[i] instanceof NameCallback) {
						final NameCallback nameCallback = (NameCallback) callback[i];
						nameCallback.setName(username);
					} else if (callback[i] instanceof PasswordCallback) {
						final PasswordCallback passCallback = (PasswordCallback) callback[i];
						passCallback.setPassword(password.toCharArray());
					} else {
						System.out
						.println("Unsupported Callback i=" + i
								+ "; class="
								+ callback[i].getClass().getName());
					}
				}
			}
		};

		return handler;
	}

	private GSSContext initGSS(final URL url, String loginentry, String user, String password) throws Exception {
		final GSSManager MANAGER = GSSManager.getInstance();

		final LoginContext loginContext = new LoginContext(loginentry,
				getUsernamePasswordHandler(user,password));
		loginContext.login();
		final Subject subject = loginContext.getSubject();

		final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
			@Override
			public GSSCredential run() throws GSSException {
				return MANAGER.createCredential(null,
						GSSCredential.DEFAULT_LIFETIME,
						new Oid("1.3.6.1.5.5.2"), GSSCredential.INITIATE_ONLY);
			}
		};

		final GSSCredential clientcreds = Subject.doAs(subject, action);

		final GSSContext context = MANAGER.createContext(MANAGER.createName(
				"HTTP@" + url.getHost(), GSSName.NT_HOSTBASED_SERVICE, new Oid(
						"1.3.6.1.5.5.2")), new Oid("1.3.6.1.5.5.2"),
						clientcreds, GSSContext.DEFAULT_LIFETIME);

		context.requestMutualAuth(true);
		context.requestConf(true);
		context.requestInteg(true);
		context.requestReplayDet(true);
		context.requestSequenceDet(true);
		context.requestCredDeleg(false);

		return context;

		/*byte[] data = context.initSecContext(new byte[0], 0, 0);




		final URLConnection uc = url.openConnection();
		uc.setRequestProperty(
				"Authorization",
				"Negotiate "
						+ org.apache.tomcat.util.codec.binary.Base64
								.encodeBase64String(data));
		uc.connect();
		data = org.apache.tomcat.util.codec.binary.Base64.decodeBase64(uc
				.getHeaderField("WWW-Authenticate").split(" ")[1]);

		data = context.initSecContext(data, 0, data.length);
		if (!context.isEstablished()) {
			throw new Exception("context not established");
		}*/

	}


}
