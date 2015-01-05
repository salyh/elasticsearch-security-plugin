package org.elasticsearch.plugins.security.http.tomcat;

import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_BLOCKING;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_BLOCKING_SERVER;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_DEFAULT_RECEIVE_BUFFER_SIZE;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_DEFAULT_SEND_BUFFER_SIZE;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_KEEP_ALIVE;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_NO_DELAY;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_RECEIVE_BUFFER_SIZE;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_REUSE_ADDRESS;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_SEND_BUFFER_SIZE;

import java.io.File;
import java.net.InetSocketAddress;
import java.util.Map;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.authenticator.SSLAuthenticator;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.deploy.FilterDef;
import org.apache.catalina.deploy.FilterMap;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.catalina.deploy.SecurityCollection;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.startup.Tomcat;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.network.NetworkUtils;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.BoundTransportAddress;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.common.unit.ByteSizeUnit;
import org.elasticsearch.common.unit.ByteSizeValue;
import org.elasticsearch.env.Environment;
import org.elasticsearch.http.HttpInfo;
import org.elasticsearch.http.HttpServerAdapter;
import org.elasticsearch.http.HttpServerTransport;
import org.elasticsearch.http.HttpStats;
import org.elasticsearch.plugins.security.service.SecurityService;
import org.elasticsearch.plugins.security.util.SecurityUtil;
import org.elasticsearch.transport.BindTransportException;

public class TomcatHttpServerTransport extends
AbstractLifecycleComponent<HttpServerTransport> implements
HttpServerTransport {

	private volatile ExtendedTomcat tomcat;

	private volatile HttpServerAdapter httpServerAdapter;

	private volatile BoundTransportAddress boundAddress;

	private final NetworkService networkService;

	private final String publishHost;

	private final String port;

	private final String bindHost;

	final ByteSizeValue maxContentLength;

	final ByteSizeValue maxHeaderSize;
	final ByteSizeValue maxChunkSize;

	private final boolean blockingServer;

	final boolean compression;

	private final int compressionLevel;

	private final Boolean tcpNoDelay;

	private final Boolean tcpKeepAlive;

	private final Boolean reuseAddress;

	private final ByteSizeValue tcpSendBufferSize;
	private final ByteSizeValue tcpReceiveBufferSize;

	private final Settings settings;

	private final SecurityService securityService;

	private final String kerberosMode;

	private final Boolean useSSL;

	private final  Boolean useClientAuth;

  final Boolean enableCors;

	static {

		System.setProperty("org.apache.catalina.connector.RECYCLE_FACADES",
				"true");
		System.setProperty(
				"org.apache.catalina.connector.CoyoteAdapter.ALLOW_BACKSLASH",
				"false");
		System.setProperty(
				"org.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH",
				"false");
		System.setProperty(
				"org.apache.catalina.connector.Response.ENFORCE_ENCODING_IN_GET_WRITER",
				"true");

		/*
		System.setProperty(
				"com.sun.net.ssl.enableECC",
				"false");

		System.setProperty(
				"jsse.enableSNIExtension",
				"false");
		 */


	}

	@Inject
	public TomcatHttpServerTransport(final Settings settings,
			final Environment environment, final NetworkService networkService,
			final ClusterName clusterName, final Client client,
			final SecurityService securityService) {
		super(settings);

		this.settings = settings;
		this.securityService = securityService;

		/*
		 * TODO check if keep alive is managed by tomcat copy custom headers to
		 * response check that user under tomcat/ea is running is not a
		 * privilieged iuser tomcat props apply: tomcat.XXX
		 */

		// _aliases test with more than one index mapped to an alias

		/*
		 * 
		 * http.max_initial_line_length not respected http.reset_cookies not
		 * respected workerCount http.cors.enabled http.cors.allow-origin
		 * http.cors.max-age http.cors.allow-methods http.cors.allow-headers
		 * 
		 * 
		 * 
		 * http://www.elasticsearch.org/guide/en/elasticsearch/reference/current/
		 * modules-network.html
		 * 
		 * http://stackoverflow.com/questions/8038718/serializing-generic-java-
		 * object-to-json-using-jackson
		 * http://tomcatspnegoad.sourceforge.net/realms.html
		 * 
		 * SSL options
		 * 
		 * 
		 * 
		 * Realm options/login waffle, spnego ... security.kerberos.provider:
		 * waffle
		 * 
		 * Hardening EA - dynamic script disable
		 */

		/*
		 * 
		 * 

		 * 
		 * 
		 * 

		 */

    enableCors = componentSettings.getAsBoolean("cors.enabled", settings.getAsBoolean("security.cors.enabled", false));

		useSSL = componentSettings.getAsBoolean("ssl.enabled",
				settings.getAsBoolean("security.ssl.enabled", false));

		useClientAuth= componentSettings.getAsBoolean("ssl.clientauth.enabled",
				settings.getAsBoolean("security.ssl.clientauth.enabled", false));

		kerberosMode = componentSettings.get("kerberos.mode",
				settings.get("security.kerberos.mode", "none"));

		port = componentSettings.get("port",
				settings.get("http.port", "8080"));
		bindHost = componentSettings.get("bind_host",
				settings.get("http.bind_host", settings.get("http.host")));
		publishHost = componentSettings.get("publish_host",
				settings.get("http.publish_host", settings.get("http.host")));
		this.networkService = networkService;

		ByteSizeValue maxContentLength = componentSettings.getAsBytesSize(
				"max_content_length", settings.getAsBytesSize(
						"http.max_content_length", new ByteSizeValue(100,
								ByteSizeUnit.MB)));
		maxChunkSize = componentSettings.getAsBytesSize(
				"max_chunk_size", settings.getAsBytesSize(
						"http.max_chunk_size", new ByteSizeValue(8,
								ByteSizeUnit.KB)));
		maxHeaderSize = componentSettings.getAsBytesSize(
				"max_header_size", settings.getAsBytesSize(
						"http.max_header_size", new ByteSizeValue(8,
								ByteSizeUnit.KB)));

		blockingServer = settings.getAsBoolean(
				"http.blocking_server",
				settings.getAsBoolean(TCP_BLOCKING_SERVER,
						settings.getAsBoolean(TCP_BLOCKING, false)));

		tcpNoDelay = componentSettings.getAsBoolean("tcp_no_delay",
				settings.getAsBoolean(TCP_NO_DELAY, true));
		tcpKeepAlive = componentSettings.getAsBoolean(
				"tcp_keep_alive", settings.getAsBoolean(TCP_KEEP_ALIVE, true));
		reuseAddress = componentSettings.getAsBoolean(
				"reuse_address",
				settings.getAsBoolean(TCP_REUSE_ADDRESS,
						NetworkUtils.defaultReuseAddress()));
		tcpSendBufferSize = componentSettings.getAsBytesSize(
				"tcp_send_buffer_size", settings.getAsBytesSize(
						TCP_SEND_BUFFER_SIZE, TCP_DEFAULT_SEND_BUFFER_SIZE));
		tcpReceiveBufferSize = componentSettings.getAsBytesSize(
				"tcp_receive_buffer_size", settings.getAsBytesSize(
						TCP_RECEIVE_BUFFER_SIZE,
						TCP_DEFAULT_RECEIVE_BUFFER_SIZE));

		compression = settings.getAsBoolean("http.compression", false);
		compressionLevel = settings.getAsInt("http.compression_level", 6);

		// validate max content length
		if (maxContentLength.bytes() > Integer.MAX_VALUE) {
			logger.warn("maxContentLength[" + maxContentLength
					+ "] set to high value, resetting it to [100mb]");
			maxContentLength = new ByteSizeValue(100, ByteSizeUnit.MB);
		}
		this.maxContentLength = maxContentLength;

		logger.debug("port: " + port);
		logger.debug("bindHost: " + bindHost);
		logger.debug("publishHost: " + publishHost);

		logger.debug("componentsettings: "
				+ componentSettings.getAsMap());
		logger.debug("settings: " + settings.getAsMap());

	}

	public SecurityService getSecurityService() {
		return securityService;
	}

	public Settings getSettings() {
		return settings;
	}

	@Override
	public BoundTransportAddress boundAddress() {
		return boundAddress;
	}

	@Override
	public HttpInfo info() {
		return new HttpInfo(boundAddress(), 0);
	}

	@Override
	public HttpStats stats() {
		return new HttpStats(0, 0);
	}

	@Override
	public void httpServerAdapter(final HttpServerAdapter httpServerAdapter) {
		this.httpServerAdapter = httpServerAdapter;

	}

	@Override
	protected void doStart() throws ElasticsearchException {
		try {

			final String currentDir = new File(".").getCanonicalPath();
			final String tomcatDir = currentDir + File.separatorChar + "tomcat";

			logger.debug("cur dir " + currentDir);

			if (tomcat != null) {
				try {
					tomcat.stop();
					tomcat.destroy();
				} catch (final Exception e) {

				}
			}

			tomcat = new ExtendedTomcat();
			tomcat.enableNaming();
			tomcat.getServer().setPort(-1); // shutdown disabled
			tomcat.getServer().setAddress("localhost");

			final String httpProtocolImpl = blockingServer ? "org.apache.coyote.http11.Http11Protocol"
					: "org.apache.coyote.http11.Http11NioProtocol";

			final Connector httpConnector = new Connector(httpProtocolImpl);
			tomcat.setConnector(httpConnector);
			tomcat.getService().addConnector(httpConnector);

			// TODO report tomcat bug with setProtocol

			if (maxContentLength != null) {
				httpConnector
				.setMaxPostSize(maxContentLength.bytesAsInt());
			}

			if (maxHeaderSize != null) {
				httpConnector.setAttribute("maxHttpHeaderSize",
						maxHeaderSize.bytesAsInt());
			}

			if (tcpNoDelay != null) {
				httpConnector.setAttribute("tcpNoDelay",
						tcpNoDelay.booleanValue());
			}

			if (reuseAddress != null) {
				httpConnector.setAttribute("socket.soReuseAddress",
						reuseAddress.booleanValue());
			}

			if (tcpKeepAlive != null) {
				httpConnector.setAttribute("socket.soKeepAlive",
						tcpKeepAlive.booleanValue());
				httpConnector.setAttribute("maxKeepAliveRequests",
						tcpKeepAlive.booleanValue() ? "100" : "1");
			}

			if (tcpReceiveBufferSize != null) {
				httpConnector.setAttribute("socket.rxBufSize",
						tcpReceiveBufferSize.bytesAsInt());
			}

			if (tcpSendBufferSize != null) {
				httpConnector.setAttribute("socket.txBufSize",
						tcpSendBufferSize.bytesAsInt());
			}

			httpConnector.setAttribute("compression",
					compression ? String.valueOf(compressionLevel)
							: "off");

			if (maxChunkSize != null) {
				httpConnector.setAttribute("maxExtensionSize",
						maxChunkSize.bytesAsInt());
			}

			httpConnector.setPort(Integer.parseInt(port));




			tomcat.setBaseDir(tomcatDir);

			final TomcatHttpTransportHandlerServlet servlet = new TomcatHttpTransportHandlerServlet();
			servlet.setTransport(this);

			final Context ctx = tomcat.addContext("", currentDir);

			logger.debug("currentDir " + currentDir);

			Tomcat.addServlet(ctx, "ES Servlet", servlet);

			ctx.addServletMapping("/*", "ES Servlet");



			if(useSSL)
			{
				logger.info("Using SSL");

				//System.setProperty("javax.net.debug", "ssl");
				httpConnector.setAttribute("SSLEnabled", "true");
				httpConnector.setSecure(true);
				httpConnector.setScheme("https");

				httpConnector.setAttribute("sslProtocol", "TLS");

				httpConnector.setAttribute("keystoreFile", settings.get(
						"security.ssl.keystorefile", "keystore"));
				httpConnector.setAttribute("keystorePass", settings.get(
						"security.ssl.keystorepass", "changeit"));
				httpConnector.setAttribute("keystoreType", settings.get(
						"security.ssl.keystoretype", "JKS"));

				final String keyalias = settings.get("security.ssl.keyalias", null);

				if(keyalias != null) {
					httpConnector.setAttribute("keyAlias", keyalias);
				}

				if(useClientAuth)
				{


					logger.info("Using SSL Client Auth (PKI), so user/roles will be retrieved from client certificate.");

					httpConnector.setAttribute("clientAuth", "true");

					httpConnector.setAttribute("truststoreFile", settings.get(
							"security.ssl.clientauth.truststorefile", "truststore"));
					httpConnector.setAttribute("truststorePass", settings.get(
							"security.ssl.clientauth.truststorepass", "changeit"));
					httpConnector.setAttribute("truststoreType", settings.get(
							"security.ssl.clientauth.truststoretype", "JKS"));


					/*final String loginconf = this.settings
						.get("security.kerberos.login.conf.path");
				final String krbconf = this.settings
						.get("security.kerberos.krb5.conf.path");

				SecurityUtil.setSystemPropertyToAbsoluteFile(
						"java.security.auth.login.config", loginconf);
				SecurityUtil.setSystemPropertyToAbsoluteFile(
						"java.security.krb5.conf", krbconf);*/

					//httpConnector.setAttribute("allowUnsafeLegacyRenegotiation", "true");

					final SecurityConstraint constraint = new SecurityConstraint();
					constraint.addAuthRole("*");
					constraint.setAuthConstraint(true);
					constraint.setUserConstraint("CONFIDENTIAL");

					final SecurityCollection col = new SecurityCollection();
					col.addPattern("/*");

          if (enableCors) {
            col.removeMethod("OPTIONS");
          }

					constraint.addCollection(col);
					ctx.addConstraint(constraint);

					final LoginConfig lc = new LoginConfig();
					lc.setAuthMethod("CLIENT-CERT");
					lc.setRealmName("clientcretificate");
					ctx.setLoginConfig(lc);



					configureJndiRealm(ctx);

					ctx.getPipeline().addValve(new SSLAuthenticator());
					logger.info("Auth Method is CLIENT-CERT");

					//http://pki-tutorial.readthedocs.org/en/latest/simple/

				}





			}else
			{
				if(useClientAuth)
				{
					logger.error("Client Auth only available with SSL");
					throw new RuntimeException("Client Auth only available with SSL");
				}

				//useClientAuth = false;
			}


			if(!useClientAuth)
			{
				if ("waffle".equalsIgnoreCase(kerberosMode)) {

					final Boolean testMode = settings.getAsBoolean(
							"security.waffle.testmode", false);

					final FilterDef fd = new FilterDef();
					fd.setFilterClass("waffle.servlet.NegotiateSecurityFilter");
					fd.setFilterName("Waffle");

					if (testMode != null && testMode.booleanValue()) {

						fd.addInitParameter("principalFormat", "fqn");
						fd.addInitParameter("roleFormat", "both");
						fd.addInitParameter("allowGuestLogin", "true");
						fd.addInitParameter("securityFilterProviders",
								"org.elasticsearch.plugins.security.waffle.TestProvider");

						logger
						.info("Kerberos implementaton is WAFFLE in testmode (only work on Windows Operations system)");
					} else {
						final Map<String, String> waffleSettings = settings
								.getByPrefix("security.waffle").getAsMap();

						for (final String waffleKey : waffleSettings.keySet()) {

							fd.addInitParameter(waffleKey.substring(1),
									waffleSettings.get(waffleKey));

							logger.debug(waffleKey.substring(1) + "="
									+ waffleSettings.get(waffleKey));

						}

						fd.addInitParameter("principalFormat", "fqn");
						fd.addInitParameter("roleFormat", "both");
						fd.addInitParameter("allowGuestLogin", "false");

						logger
						.info("Kerberos implementaton is WAFFLE (only work on Windows Operations system)");
					}

					ctx.addFilterDef(fd);
					final FilterMap fm = new FilterMap();
					fm.setFilterName("Waffle");
					fm.addURLPattern("/*");
					ctx.addFilterMap(fm);

				} else if ("spnegoad".equalsIgnoreCase(kerberosMode)) {

					//System.setProperty("sun.security.krb5.debug", "true"); // TODO
					// switch
					// off

					System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");

					final SecurityConstraint constraint = new SecurityConstraint();
					constraint.addAuthRole("*");
					constraint.setAuthConstraint(true);
					constraint.setDisplayName("spnego_sc_all");
					final SecurityCollection col = new SecurityCollection();
					col.addPattern("/*");

          if (enableCors) {
            col.removeMethod("OPTIONS");
          }

					constraint.addCollection(col);
					ctx.addConstraint(constraint);

					final LoginConfig lc = new LoginConfig();
					lc.setAuthMethod("SPNEGO");
					lc.setRealmName("SPNEGO");
					ctx.setLoginConfig(lc);

					logger
					.info("Kerberos implementaton is SPNEGOAD");

					configureJndiRealm(ctx);

					final ExtendedSpnegoAuthenticator spnegoValve = new ExtendedSpnegoAuthenticator();
					//spnegoValve.setLoginConfigName("es-login");
					spnegoValve.setStoreDelegatedCredential(true);
					ctx.getPipeline().addValve(spnegoValve);

					//final SpnegoAuthenticator spnegoValve = new SpnegoAuthenticator();
					//spnegoValve.setLoginEntryName("es-login");
					//ctx.getPipeline().addValve(spnegoValve);



				} else if ("none".equalsIgnoreCase(kerberosMode)) {

					logger
					.warn("Kerberos is not configured so user/roles are unavailable. Host based security, in contrast, is woking. ");

				} else {
					logger
					.error("No Kerberos implementaion '"
							+ kerberosMode
							+ "' found. Kerberos is therefore not configured so user/roles are unavailable. Host based security, in contrast, is woking. ");
				}
			}

			tomcat.start();

			logger.info("Tomcat started");

			InetSocketAddress bindAddress;
			try {
				bindAddress = new InetSocketAddress(
						networkService
						.resolveBindHostAddress(bindHost),
						tomcat.getConnector().getLocalPort());
			} catch (final Exception e) {
				throw new BindTransportException(
						"Failed to resolve bind address", e);
			}

			InetSocketAddress publishAddress;
			try {
				publishAddress = new InetSocketAddress(
						networkService
						.resolvePublishHostAddress(publishHost),
						bindAddress.getPort());
			} catch (final Exception e) {
				throw new BindTransportException(
						"Failed to resolve publish address", e);
			}

			logger.debug("bindAddress " + bindAddress);
			logger.debug("publishAddress " + publishAddress);

			boundAddress = new BoundTransportAddress(
					new InetSocketTransportAddress(bindAddress),
					new InetSocketTransportAddress(publishAddress));

		} catch (final Exception e) {
			throw new ElasticsearchException("Unable to start Tomcat", e);
		}

	}

	@Override
	protected void doStop() throws ElasticsearchException {

		try {
			if (tomcat != null) {
				tomcat.stop();
			}

		} catch (final Exception e) {
			throw new ElasticsearchException("Unable to stop Tomcat", e);
		}

	}

	public HttpServerAdapter httpServerAdapter() {
		return httpServerAdapter;
	}

	@Override
	protected void doClose() throws ElasticsearchException {
		try {
			tomcat.destroy();
			tomcat = null;
		} catch (final LifecycleException e) {
			throw new ElasticsearchException("Unable to destroy Tomcat", e);
		}

	}


	protected void configureJndiRealm(Context ctx)
	{

		final String[] ldapurls = settings
				.get("security.authorization.ldap.ldapurls").split(",");

		final String sslroleattribute = settings
				.get("security.ssl.userattribute");

		//final Boolean isLdapAD = this.settings.getAsBoolean(
		//	"security.authorization.ldap.isactivedirectory", true);

		final String loginconf = settings
				.get("security.kerberos.login.conf.path");
		final String krbconf = settings
				.get("security.kerberos.krb5.conf.path");

		SecurityUtil.setSystemPropertyToAbsoluteFile(
				"java.security.auth.login.config", loginconf);
		SecurityUtil.setSystemPropertyToAbsoluteFile(
				"java.security.krb5.conf", krbconf);

		//final ExtendedJndiRealm realm = new ExtendedJndiRealm();

		final ExtendedJndiRealm realm = new ExtendedJndiRealm (sslroleattribute);
		//realm.setConnectionName("uid=admin,ou=system");
		//realm.setConnectionPassword("secret");

		realm.setConnectionURL(ldapurls[0].trim());
		
		if(ldapurls.length > 1) {
		    realm.setAlternateURL(ldapurls[1].trim());
		}

		realm.setAuthentication("simple");
		realm.setUseDelegatedCredential(false);

		realm.setUserSubtree(true);
		realm.setRoleSubtree(true);

		realm.setReferrals("follow");
		realm.setUserSearch("(sAMAccountName={0})");
		realm.setRoleSearch("(member={0})");
		realm.setRoleName("cn");




		/*realm.setUserSearch("uid={0}");
		realm.setRoleSearch("(member={0})");
		realm.setRoleName("cn");
		realm.setUserBase("ou=users,dc=example,dc=com");
		realm.setRoleBase("ou=groups,dc=example,dc=com");
		 */

		realm.setConnectionName(settings.get(
				"security.authorization.ldap.connectionname",
				realm.getConnectionName()));

		realm.setConnectionPassword(settings.get(
				"security.authorization.ldap.connectionpassword",
				realm.getConnectionPassword()));

		realm.setUserBase(settings.get(
				"security.authorization.ldap.userbase",
				realm.getUserBase()));
		realm.setUserSearch(settings.get(
				"security.authorization.ldap.usersearch",
				realm.getUserSearch()));
		realm.setRoleBase(settings.get(
				"security.authorization.ldap.rolebase",
				realm.getRoleBase()));
		realm.setRoleSearch(settings.get(
				"security.authorization.ldap.rolesearch",
				realm.getRoleSearch()));
		realm.setRoleName(settings.get(
				"security.authorization.ldap.rolename",
				realm.getRoleName()));






		//realm.setAuthentication("EXTERNAL");
		//realm.setProtocol("ssl");

		//http://docs.oracle.com/javase/tutorial/jndi/ldap/ssl.html#EXTERNAL
		//https://issues.apache.org/bugzilla/show_bug.cgi?id=55778
		//http://docs.oracle.com/javase/jndi/tutorial/ldap/security/sasl.html


		ctx.setRealm(realm );
		//ctx.setRealm(new AllPermsRealm());

	}



	/*
	 * protected void configureLdapRealm(Context ctx)
	{

		final String ldapurls = this.settings
				.get("security.authorization.ldap.ldapurls");

		final Boolean isLdapAD = this.settings.getAsBoolean(
				"security.authorization.ldap.isactivedirectory", true);

		final String loginconf = this.settings
				.get("security.kerberos.login.conf.path");
		final String krbconf = this.settings
				.get("security.kerberos.krb5.conf.path");

		SecurityUtil.setSystemPropertyToAbsoluteFile(
				"java.security.auth.login.config", loginconf);
		SecurityUtil.setSystemPropertyToAbsoluteFile(
				"java.security.krb5.conf", krbconf);

		final ContextResource resource = new ContextResource();
		resource.setType("net.sf.michaelo.dirctxsrc.DirContextSource");
		resource.setName("active-directory");
		resource.setProperty("factory",
				"net.sf.michaelo.dirctxsrc.DirContextSourceFactory");
		resource.setProperty("auth", "gssapi");
		resource.setProperty("urls", ldapurls);
		resource.setProperty("loginEntryName", "es-ldap-server");
		ctx.getNamingResources().addResource(resource);

		if (isLdapAD != null && isLdapAD.booleanValue()) {

			this.logger
					.info("LDAP server is Active Directory");

			final FixedActiveDirectoryRealm realm = new FixedActiveDirectoryRealm();
			realm.setResourceName("active-directory");
			realm.setLocalResource(true);
			ctx.setRealm(realm);

		} else {

			this.logger
					.info("LDAP server is NOT Active Directory");
			final UniversalLdapRealm realm = new UniversalLdapRealm();

			realm.setUserSearchBase(this.settings.get(
					"security.authorization.ldap.usersearchbase",
					realm.getUserSearchBase()));
			realm.setUsersSearchPattern(this.settings.get(
					"security.authorization.ldap.usersearchpattern",
					realm.getUsersSearchPattern()));
			realm.setGroupsSearchBase(this.settings.get(
					"security.authorization.ldap.groupssearchbase",
					realm.getGroupsSearchBase()));
			realm.setGroupsSearchPattern(this.settings.get(
					"security.authorization.ldap.groupssearchpattern",
					realm.getGroupsSearchPattern()));
			realm.setRoleNameAttribute(this.settings.get(
					"security.authorization.ldap.rolenameattribute",
					realm.getRoleNameAttribute()));

			realm.setResourceName("active-directory");
			realm.setLocalResource(true);
			ctx.setRealm(realm);
		}}
	 */


}
