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

import net.sf.michaelo.tomcat.authenticator.SpnegoAuthenticator;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.deploy.ContextResource;
import org.apache.catalina.deploy.FilterDef;
import org.apache.catalina.deploy.FilterMap;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.catalina.deploy.SecurityCollection;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.startup.Tomcat;
import org.elasticsearch.ElasticSearchException;
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

	private final String kerberosImpl;

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

		this.kerberosImpl = this.componentSettings.get("kerberosimpl",
				settings.get("security.kerberosimpl", "none"));

		this.port = this.componentSettings.get("port",
				settings.get("http.port", "8080"));
		this.bindHost = this.componentSettings.get("bind_host",
				settings.get("http.bind_host", settings.get("http.host")));
		this.publishHost = this.componentSettings.get("publish_host",
				settings.get("http.publish_host", settings.get("http.host")));
		this.networkService = networkService;

		ByteSizeValue maxContentLength = this.componentSettings.getAsBytesSize(
				"max_content_length", settings.getAsBytesSize(
						"http.max_content_length", new ByteSizeValue(100,
								ByteSizeUnit.MB)));
		this.maxChunkSize = this.componentSettings.getAsBytesSize(
				"max_chunk_size", settings.getAsBytesSize(
						"http.max_chunk_size", new ByteSizeValue(8,
								ByteSizeUnit.KB)));
		this.maxHeaderSize = this.componentSettings.getAsBytesSize(
				"max_header_size", settings.getAsBytesSize(
						"http.max_header_size", new ByteSizeValue(8,
								ByteSizeUnit.KB)));

		this.blockingServer = settings.getAsBoolean(
				"http.blocking_server",
				settings.getAsBoolean(TCP_BLOCKING_SERVER,
						settings.getAsBoolean(TCP_BLOCKING, false)));

		this.tcpNoDelay = this.componentSettings.getAsBoolean("tcp_no_delay",
				settings.getAsBoolean(TCP_NO_DELAY, true));
		this.tcpKeepAlive = this.componentSettings.getAsBoolean(
				"tcp_keep_alive", settings.getAsBoolean(TCP_KEEP_ALIVE, true));
		this.reuseAddress = this.componentSettings.getAsBoolean(
				"reuse_address",
				settings.getAsBoolean(TCP_REUSE_ADDRESS,
						NetworkUtils.defaultReuseAddress()));
		this.tcpSendBufferSize = this.componentSettings.getAsBytesSize(
				"tcp_send_buffer_size", settings.getAsBytesSize(
						TCP_SEND_BUFFER_SIZE, TCP_DEFAULT_SEND_BUFFER_SIZE));
		this.tcpReceiveBufferSize = this.componentSettings.getAsBytesSize(
				"tcp_receive_buffer_size", settings.getAsBytesSize(
						TCP_RECEIVE_BUFFER_SIZE,
						TCP_DEFAULT_RECEIVE_BUFFER_SIZE));

		this.compression = settings.getAsBoolean("http.compression", false);
		this.compressionLevel = settings.getAsInt("http.compression_level", 6);

		// validate max content length
		if (maxContentLength.bytes() > Integer.MAX_VALUE) {
			this.logger.warn("maxContentLength[" + maxContentLength
					+ "] set to high value, resetting it to [100mb]");
			maxContentLength = new ByteSizeValue(100, ByteSizeUnit.MB);
		}
		this.maxContentLength = maxContentLength;

		this.logger.debug("port: " + this.port);
		this.logger.debug("bindHost: " + this.bindHost);
		this.logger.debug("publishHost: " + this.publishHost);

		this.logger.debug("componentsettings: "
				+ this.componentSettings.getAsMap());
		this.logger.debug("settings: " + settings.getAsMap());

	}

	public SecurityService getSecurityService() {
		return this.securityService;
	}

	public Settings getSettings() {
		return this.settings;
	}

	@Override
	public BoundTransportAddress boundAddress() {
		return this.boundAddress;
	}

	@Override
	public HttpInfo info() {
		return new HttpInfo(this.boundAddress(), 0);
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
	protected void doStart() throws ElasticSearchException {
		try {

			final String currentDir = new File(".").getCanonicalPath();
			final String tomcatDir = currentDir + File.separatorChar + "tomcat";

			this.logger.debug("cur dir " + currentDir);

			if (this.tomcat != null) {
				try {
					this.tomcat.stop();
					this.tomcat.destroy();
				} catch (final Exception e) {

				}
			}

			this.tomcat = new ExtendedTomcat();
			this.tomcat.enableNaming();
			this.tomcat.getServer().setPort(-1); // shutdown disabled
			this.tomcat.getServer().setAddress("localhost");

			final String httpProtocolImpl = this.blockingServer ? "org.apache.coyote.http11.Http11Protocol"
					: "org.apache.coyote.http11.Http11NioProtocol";

			final Connector httpConnector = new Connector(httpProtocolImpl);
			this.tomcat.setConnector(httpConnector);
			this.tomcat.getService().addConnector(httpConnector);

			// TODO report tomcat bug with setProtocol

			if (this.maxContentLength != null) {
				httpConnector
						.setMaxPostSize(this.maxContentLength.bytesAsInt());
			}

			if (this.maxHeaderSize != null) {
				httpConnector.setAttribute("maxHttpHeaderSize",
						this.maxHeaderSize.bytesAsInt());
			}

			if (this.tcpNoDelay != null) {
				httpConnector.setAttribute("tcpNoDelay",
						this.tcpNoDelay.booleanValue());
			}

			if (this.reuseAddress != null) {
				httpConnector.setAttribute("socket.soReuseAddress",
						this.reuseAddress.booleanValue());
			}

			if (this.tcpKeepAlive != null) {
				httpConnector.setAttribute("socket.soKeepAlive",
						this.tcpKeepAlive.booleanValue());
				httpConnector.setAttribute("maxKeepAliveRequests",
						this.tcpKeepAlive.booleanValue() ? "100" : "1");
			}

			if (this.tcpReceiveBufferSize != null) {
				httpConnector.setAttribute("socket.rxBufSize",
						this.tcpReceiveBufferSize.bytesAsInt());
			}

			if (this.tcpSendBufferSize != null) {
				httpConnector.setAttribute("socket.txBufSize",
						this.tcpSendBufferSize.bytesAsInt());
			}

			httpConnector.setAttribute("compression",
					this.compression ? String.valueOf(this.compressionLevel)
							: "off");

			if (this.maxChunkSize != null) {
				httpConnector.setAttribute("maxExtensionSize",
						this.maxChunkSize.bytesAsInt());
			}

			httpConnector.setPort(Integer.parseInt(this.port));

			this.tomcat.setBaseDir(tomcatDir);

			final TomcatHttpTransportHandlerServlet servlet = new TomcatHttpTransportHandlerServlet();
			servlet.setTransport(this);

			final Context ctx = this.tomcat.addContext("", currentDir);

			this.logger.debug("currentDir " + currentDir);

			Tomcat.addServlet(ctx, "ES Servlet", servlet);

			ctx.addServletMapping("/*", "ES Servlet");

			if ("waffle".equalsIgnoreCase(this.kerberosImpl)) {

				final Boolean testMode = this.settings.getAsBoolean(
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

					this.logger
							.info("Kerberos implementaton is WAFFLE in testmode (only work on Windows Operations system)");
				} else {
					final Map<String, String> waffleSettings = this.settings
							.getByPrefix("security.waffle").getAsMap();

					for (final String waffleKey : waffleSettings.keySet()) {

						fd.addInitParameter(waffleKey.substring(1),
								waffleSettings.get(waffleKey));

						this.logger.debug(waffleKey.substring(1) + "="
								+ waffleSettings.get(waffleKey));

					}

					fd.addInitParameter("principalFormat", "fqn");
					fd.addInitParameter("roleFormat", "both");
					fd.addInitParameter("allowGuestLogin", "false");

					this.logger
							.info("Kerberos implementaton is WAFFLE (only work on Windows Operations system)");
				}

				ctx.addFilterDef(fd);
				final FilterMap fm = new FilterMap();
				fm.setFilterName("Waffle");
				fm.addURLPattern("/*");
				ctx.addFilterMap(fm);

			} else if ("spnegoad".equalsIgnoreCase(this.kerberosImpl)) {

				System.setProperty("sun.security.krb5.debug", "true"); // TODO
																		// switch
																		// off

				final SecurityConstraint constraint = new SecurityConstraint();
				constraint.addAuthRole("*");
				constraint.setAuthConstraint(true);
				final SecurityCollection col = new SecurityCollection();
				col.addPattern("/*");

				constraint.addCollection(col);
				ctx.addConstraint(constraint);

				final LoginConfig lc = new LoginConfig();
				lc.setAuthMethod("SPNEGO");
				lc.setRealmName("SPNEGO");
				ctx.setLoginConfig(lc);

				{

					final String ldapurls = this.settings
							.get("security.spnegoad.ldapurls");
					final Boolean isLdapAD = this.settings.getAsBoolean(
							"security.spnegoad.isactivedirectory", true);

					final String loginconf = this.settings
							.get("security.spnegoad.login.conf.path");
					final String krbconf = this.settings
							.get("security.spnegoad.krb5.conf.path");

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
								.info("Kerberos implementaton is SPNEGOAD (LDAP server is Active Directory)");

						final FixedActiveDirectoryRealm realm = new FixedActiveDirectoryRealm();
						realm.setResourceName("active-directory");
						realm.setLocalResource(true);
						ctx.setRealm(realm);

					} else {

						this.logger
								.info("Kerberos implementaton is SPNEGOAD (LDAP server is non an Active Directory)");
						final UniversalLdapRealm realm = new UniversalLdapRealm();

						realm.setUserSearchBase(this.settings.get(
								"security.spnegoad.ldap.usersearchbase",
								realm.getUserSearchBase()));
						realm.setUsersSearchPattern(this.settings.get(
								"security.spnegoad.ldap.usersearchpattern",
								realm.getUsersSearchPattern()));
						realm.setGroupsSearchBase(this.settings.get(
								"security.spnegoad.ldap.groupssearchbase",
								realm.getGroupsSearchBase()));
						realm.setGroupsSearchPattern(this.settings.get(
								"security.spnegoad.ldap.groupssearchpattern",
								realm.getGroupsSearchPattern()));
						realm.setRoleNameAttribute(this.settings.get(
								"security.spnegoad.ldap.rolenameattribute",
								realm.getRoleNameAttribute()));

						realm.setResourceName("active-directory");
						realm.setLocalResource(true);
						ctx.setRealm(realm);
					}

					final SpnegoAuthenticator spnegoValve = new SpnegoAuthenticator();
					spnegoValve.setLoginEntryName("es-login");
					ctx.getPipeline().addValve(spnegoValve);

				}

			} else if ("none".equalsIgnoreCase(this.kerberosImpl)) {

				this.logger
						.warn("Kerberos is not configured so user/roles are unavailable. Host based security, in contrast, is woking. ");

			} else {
				this.logger
						.error("No Kerberos implementaion '"
								+ this.kerberosImpl
								+ "' found. Kerberos is therefore not configured so user/roles are unavailable. Host based security, in contrast, is woking. ");
			}

			this.tomcat.start();

			InetSocketAddress bindAddress;
			try {
				bindAddress = new InetSocketAddress(
						this.networkService
								.resolveBindHostAddress(this.bindHost),
						this.tomcat.getConnector().getLocalPort());
			} catch (final Exception e) {
				throw new BindTransportException(
						"Failed to resolve bind address", e);
			}

			InetSocketAddress publishAddress;
			try {
				publishAddress = new InetSocketAddress(
						this.networkService
								.resolvePublishHostAddress(this.publishHost),
						bindAddress.getPort());
			} catch (final Exception e) {
				throw new BindTransportException(
						"Failed to resolve publish address", e);
			}

			this.logger.debug("bindAddress " + bindAddress);
			this.logger.debug("publishAddress " + publishAddress);

			this.boundAddress = new BoundTransportAddress(
					new InetSocketTransportAddress(bindAddress),
					new InetSocketTransportAddress(publishAddress));

		} catch (final Exception e) {
			throw new ElasticSearchException("Unable to start Tomcat", e);
		}

	}

	@Override
	protected void doStop() throws ElasticSearchException {

		try {
			if (this.tomcat != null) {
				this.tomcat.stop();
			}

		} catch (final Exception e) {
			throw new ElasticSearchException("Unable to stop Tomcat", e);
		}

	}

	public HttpServerAdapter httpServerAdapter() {
		return this.httpServerAdapter;
	}

	@Override
	protected void doClose() throws ElasticSearchException {
		try {
			this.tomcat.destroy();
			this.tomcat = null;
		} catch (final LifecycleException e) {
			throw new ElasticSearchException("Unable to destroy Tomcat", e);
		}

	}

}
