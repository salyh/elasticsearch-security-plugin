package org.elasticsearch.plugins.security;

import java.util.Properties;

import org.apache.directory.api.ldap.model.constants.SupportedSaslMechanisms;
import org.apache.directory.server.annotations.CreateKdcServer;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.annotations.SaslMechanism;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreateIndex;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.ldap.handlers.sasl.cramMD5.CramMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.digestMD5.DigestMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.gssapi.GssapiMechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.ntlm.NtlmMechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.plain.PlainMechanismHandler;
import org.elasticsearch.plugins.security.util.SecurityUtil;
import org.junit.Before;
import org.junit.runner.RunWith;
@RunWith(FrameworkRunner.class)
@CreateDS(name = "SaslGssapiBindITest-class", partitions = { @CreatePartition(name = "example", suffix = "dc=example,dc=com", contextEntry = @ContextEntry(entryLdif = "dn: dc=example,dc=com\n"
		+ "dc: example\n" + "objectClass: top\n" + "objectClass: domain\n\n"), indexes = {
	@CreateIndex(attribute = "objectClass"),
	@CreateIndex(attribute = "dc"), @CreateIndex(attribute = "ou") }) }, additionalInterceptors = { KeyDerivationInterceptor.class })
@CreateLdapServer(allowAnonymousAccess=true, transports = { @CreateTransport(protocol = "LDAP", port = 6389) }, saslHost = "localhost", saslPrincipal = "ldap/localhost@EXAMPLE.COM", saslMechanisms = {
		@SaslMechanism(name = SupportedSaslMechanisms.PLAIN, implClass = PlainMechanismHandler.class),
		@SaslMechanism(name = SupportedSaslMechanisms.CRAM_MD5, implClass = CramMd5MechanismHandler.class),
		@SaslMechanism(name = SupportedSaslMechanisms.DIGEST_MD5, implClass = DigestMd5MechanismHandler.class),
		@SaslMechanism(name = SupportedSaslMechanisms.GSSAPI, implClass = GssapiMechanismHandler.class),
		@SaslMechanism(name = SupportedSaslMechanisms.NTLM, implClass = NtlmMechanismHandler.class),
		@SaslMechanism(name = SupportedSaslMechanisms.GSS_SPNEGO, implClass = NtlmMechanismHandler.class) })
@CreateKdcServer(transports = {
		@CreateTransport(protocol = "UDP", port = 6088, address = "localhost"),
		@CreateTransport(protocol = "TCP", port = 6088, address = "localhost") })
public class SslSpnegoAdTests extends SpnegoAdTests {

	@Override
	protected Properties getProperties() {
		final Properties props = new Properties();
		props.putAll(super.getProperties());

		props.setProperty("security.ssl.enabled", "true");
		props.setProperty("security.ssl.keystorefile", SecurityUtil.getAbsoluteFilePathFromClassPath("localhost_tc.p12").getAbsolutePath()); //"C:\\cygwin\\home\\salyh\\pki-simple\\v2\\certs\\localhost_tc.p12
		props.setProperty("security.ssl.keystoretype", "PKCS12");

		props.setProperty("security.ssl.clientauth.enabled", "true");
		props.setProperty("security.ssl.clientauth.truststorefile", SecurityUtil.getAbsoluteFilePathFromClassPath("truststore.jks").getAbsolutePath());

		props.setProperty("security.ssl.userattribute","CN");
		//props.setProperty("security.module.actionpathfilter.enabled", "false");
		//props.setProperty("security.module.dls.enabled", "false");



		return props;
	}


	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();

	}

	@Override
	protected boolean isSSL() {
		return true;
	}

	/*
	@Test
	public void testSSL() throws Exception

	{

		final String krbConfPath = URLDecoder.decode(this.getClass()
				.getClassLoader().getResource("krb5.conf").getFile(),
				"UTF-8");

		System.setProperty("java.security.krb5.conf", krbConfPath);
		System.setProperty("sun.security.krb5.debug", "true");

		SecurityUtil.setSystemPropertyToAbsoluteFilePathFromClassPath("java.security.auth.login.config", "login.conf");

		System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");

		KeyStore myTrustStore = KeyStore.getInstance("PKCS12");
		myTrustStore.load(new FileInputStream(SecurityUtil.getAbsoluteFilePathFromClassPath("localhost_tc.p12")), "changeit".toCharArray());

		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(new FileInputStream(SecurityUtil.getAbsoluteFilePathFromClassPath("hnelsonclient.p12")), "changeit".toCharArray());



		SSLContext sslContext = SSLContexts.custom()
		   .useTLS()
		       .loadKeyMaterial(keyStore, "changeit".toCharArray())
		       .loadTrustMaterial(myTrustStore)

		   .build();



		SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext);

		CloseableHttpClient httpclient = HttpClients.custom()

				.setSSLSocketFactory(sslsf)
		        .build();


		final ClientConfig clientConfig1 = new ClientConfig.Builder("https://localhost:8080/")
		.multiThreaded(true).build();

// Construct a new Jest client according to configuration via factory
		JestClientFactory factory1 = new JestClientFactory();

		factory1.setClientConfig(clientConfig1);

		JestHttpClient c = (JestHttpClient) factory1.getObject();
		c.setHttpClient(httpclient);

		JestResult res = c.execute(new Index.Builder(this
				.loadFile("ur_test_normal.json"))
				.index("securityconfiguration").type("actionpathfilter")
				.id("actionpathfilter").refresh(true)
				.setHeader("Authorization", "foo bar").build());


		res = c.execute(new Search.Builder(this
				.loadFile("field_query.json")).refresh(true)
				.setHeader("Authorization", "foo bar").build());

		this.log.info(res.getJsonString());
		Assert.assertTrue(res.isSucceeded());

}*/
}
