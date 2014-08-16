package org.elasticsearch.plugins.security;

import java.net.URL;
import java.util.Hashtable;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.security.auth.kerberos.KerberosPrincipal;

import net.sourceforge.spnego.SpnegoHttpURLConnection;

import org.apache.commons.io.IOUtils;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.constants.SupportedSaslMechanisms;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.server.annotations.CreateKdcServer;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.annotations.SaslMechanism;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreateIndex;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.apache.directory.server.core.jndi.CoreContextFactory;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.kerberos.kdc.KdcServer;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.sasl.cramMD5.CramMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.digestMD5.DigestMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.gssapi.GssapiMechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.ntlm.NtlmMechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.plain.PlainMechanismHandler;
import org.elasticsearch.plugins.security.util.SecurityUtil;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
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
public class SpnegoAdTests extends SpnegoTests {

	/*public static CallbackHandler getUsernamePasswordHandler(
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

	protected void initGSS(final URL url) throws Exception {
		final GSSManager MANAGER = GSSManager.getInstance();

		final LoginContext loginContext = new LoginContext("spnego-client",
				getUsernamePasswordHandler("hnelson", "secret"));
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
		byte[] data = context.initSecContext(new byte[0], 0, 0);

		final URLConnection uc = url.openConnection();
		uc.setRequestProperty("Authorization",
				"Negotiate " + org.apache.tomcat.util.codec.binary.Base64.encodeBase64String(data));
		uc.connect();
		data = org.apache.tomcat.util.codec.binary.Base64
				.decodeBase64(uc.getHeaderField("WWW-Authenticate").split(" ")[1]);

		data = context.initSecContext(data, 0, data.length);
		if (!context.isEstablished()) {
			throw new Exception("context not established");
		}

	}

	@Test
	public void getHeaderTest() throws Exception {
		final URL url = new URL("http://localhost:8080");

		SecurityUtil.setSystemPropertyToAbsoluteFilePathFromClassPath(
				"java.security.auth.login.config", "login.conf");
		this.initGSS(url);

	}*/

	// public static final String AUTHN_HEADER = "WWW-Authenticate";
	// public static final String AUTHZ_HEADER = "Authorization";

	private DirContext ctx;

	/** the context root for the schema */
	protected LdapContext schemaRoot;

	/** the context root for the system partition */
	protected LdapContext sysRoot;

	/** the context root for the rootDSE */
	protected CoreSession rootDse;

	/** The used DirectoryService instance */
	public static DirectoryService service;

	/** The used LdapServer instance */
	public static LdapServer ldapServer;

	/** The used KdcServer instance */
	public static KdcServer kdcServer;

	public static DirectoryService getService() {
		return service;
	}

	public static void setService(final DirectoryService service) {
		SpnegoAdTests.service = service;
	}

	public static LdapServer getLdapServer() {
		return ldapServer;
	}

	public static void setLdapServer(final LdapServer ldapServer) {
		SpnegoAdTests.ldapServer = ldapServer;
	}

	public static KdcServer getKdcServer() {
		return kdcServer;
	}

	public static void setKdcServer(final KdcServer kdcServer) {
		SpnegoAdTests.kdcServer = kdcServer;
	}

	@Override
	protected Properties getProperties() {
		final Properties props = new Properties();
		props.putAll(super.getProperties());
		props.setProperty("security.kerberos.mode", "spnegoad");
		props.setProperty("security.authorization.ldap.isactivedirectory", "false");
		props.setProperty("security.authorization.ldap.ldapurls", "ldap://localhost:6389");

		props.setProperty("security.authorization.ldap.connectionname", "uid=admin,ou=system");
		props.setProperty("security.authorization.ldap.connectionpassword", "secret");
		props.setProperty("security.authorization.ldap.usersearch", "uid={0}");
		props.setProperty("security.authorization.ldap.userbase", "ou=users,dc=example,dc=com");
		props.setProperty("security.authorization.ldap.rolebase", "ou=groups,dc=example,dc=com");


		props.setProperty("security.kerberos.login.conf.path", SecurityUtil.getAbsoluteFilePathFromClassPath("login.conf").getAbsolutePath());
		props.setProperty("security.kerberos.krb5.conf.path", SecurityUtil.getAbsoluteFilePathFromClassPath("krb5.conf").getAbsolutePath());

		//props.setProperty("security.module.actionpathfilter.enabled", "false");
		//props.setProperty("security.module.dls.enabled", "false");

		return props;
	}



	public SpnegoAdTests() {
		super();


	}


	@Override
	protected String [] getUserPass()
	{
		return new String[]{"hnelson", "secret"};
	}

	@Test
	public void spneghc() throws Exception {

		kdcServer.getConfig().setPaEncTimestampRequired(false);

		executeIndex("dls_default_test_allowall.json",
				"securityconfiguration", "dlspermissions", "default", true);

		executeIndex("dls_default_test_allowall.json",
				"securityconfiguration", "dlspermissions", "default", true);

	}

	@Test
	public void donothing() throws Exception {

	}


	@Test
	public void queryGETUrlTest() throws Exception {

		if(isSSL()) {
			return;
		}

		executeIndex("dls_default_test_allowall.json",
				"securityconfiguration", "dlspermissions", "default", true);

		executeIndex("dls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);

		executeIndex("test_normal.json", "securityconfiguration", "actionpathfilter", "actionpathfilter",true );
		executeIndex("dummy_content.json", "twitter",
				"tweet", "1", true);



		final net.sourceforge.spnego.SpnegoHttpURLConnection hcon = new SpnegoHttpURLConnection(
				"spnego-client", "hnelson@EXAMPLE.COM", "secret");

		hcon.requestCredDeleg(true);


		hcon.connect(new URL(getServerUri() + "/_search"));
		//hcon.connect(new URL(getServerUri() + "/%5Fsearch"));

		Assert.assertTrue(hcon.getResponseCode() == 200);

		log.debug(IOUtils.toString(hcon.getInputStream()));





	}



	public static String fixServicePrincipalName(String servicePrincipalName,
			final Dn serviceEntryDn, final LdapServer ldapServer)
					throws LdapException {
		final KerberosPrincipal servicePrincipal = new KerberosPrincipal(
				servicePrincipalName, KerberosPrincipal.KRB_NT_SRV_HST);
		servicePrincipalName = servicePrincipal.getName();

		ldapServer.setSaslPrincipal(servicePrincipalName);

		if (serviceEntryDn != null) {
			final ModifyRequest modifyRequest = new ModifyRequestImpl();
			modifyRequest.setName(serviceEntryDn);
			modifyRequest.replace("userPassword", "randall");
			modifyRequest.replace("krb5PrincipalName", servicePrincipalName);
			ldapServer.getDirectoryService().getAdminSession()
			.modify(modifyRequest);
		}

		return servicePrincipalName;
	}

	/**
	 * Set up a partition for EXAMPLE.COM and add user and service principals to
	 * test authentication with.
	 */
	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();

		getKdcServer().getConfig().setPrimaryRealm("EXAMPLE.COM");

		final String servicePrincipalName = fixServicePrincipalName(
				"ldap/localhost@EXAMPLE.COM", null, getLdapServer());

		// System.out.println("servicePrincipalName "+servicePrincipalName);

		Attributes attrs;

		this.setContexts("uid=admin,ou=system", "secret");

		// -------------------------------------------------------------------
		// Enable the krb5kdc schema
		// -------------------------------------------------------------------

		// check if krb5kdc is disabled
		final Attributes krb5kdcAttrs = schemaRoot
				.getAttributes("cn=Krb5kdc");
		boolean isKrb5KdcDisabled = false;

		if (krb5kdcAttrs.get("m-disabled") != null) {
			isKrb5KdcDisabled = ((String) krb5kdcAttrs.get("m-disabled").get())
					.equalsIgnoreCase("TRUE");
		}

		// if krb5kdc is disabled then enable it
		if (isKrb5KdcDisabled) {
			final Attribute disabled = new BasicAttribute("m-disabled");
			final ModificationItem[] mods = new ModificationItem[] { new ModificationItem(
					DirContext.REMOVE_ATTRIBUTE, disabled) };
			schemaRoot.modifyAttributes("cn=Krb5kdc", mods);
		}

		// Get a context, create the ou=users subcontext, then create the 3
		// principals.
		final Hashtable<String, Object> env = new Hashtable<String, Object>();
		env.put(DirectoryService.JNDI_KEY, getService());
		env.put(Context.INITIAL_CONTEXT_FACTORY,
				"org.apache.directory.server.core.jndi.CoreContextFactory");
		env.put(Context.PROVIDER_URL, "dc=example,dc=com");
		env.put(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
		env.put(Context.SECURITY_CREDENTIALS, "secret");
		env.put(Context.SECURITY_AUTHENTICATION, "simple");

		ctx = new InitialDirContext(env);

		attrs = getOrgUnitAttributes("users");
		final DirContext users = ctx.createSubcontext("ou=users", attrs);

		attrs = getPrincipalAttributes("Nelson", "Horatio Nelson",
				"hnelson", "secret", "hnelson@EXAMPLE.COM");
		users.createSubcontext("uid=hnelson", attrs);

		attrs = getPrincipalAttributes("hNelson", "Horatio hNelson",
				"nelsonh", "secret", "nelsonh@EXAMPLE.COM");
		users.createSubcontext("uid=nelsonh", attrs);

		attrs = getPrincipalAttributes("Einstein", "Albert Einstein",
				"aeinstein", "aeinstein", "aeinstein@EXAMPLE.COM");
		users.createSubcontext("uid=aeinstein", attrs);

		attrs = getPrincipalAttributes("Service", "KDC Service", "krbtgt",
				"secret", "krbtgt/EXAMPLE.COM@EXAMPLE.COM");
		users.createSubcontext("uid=krbtgt", attrs);

		attrs = getPrincipalAttributes("Service", "LDAP Service", "ldap",
				"randall", servicePrincipalName);
		users.createSubcontext("uid=ldap", attrs);

		attrs = getPrincipalAttributes("Service", "HTTP Service", "http",
				"httppwd", "HTTP/localhost@EXAMPLE.COM");
		users.createSubcontext("uid=http", attrs);

		/*
		 * dn: cn=itpeople,ou=groups,dc=example,dc=com objectclass: groupofnames
		 * cn: itpeople description: IT security group member: cn=William
		 * Smith,ou=people,dc=example,dc=com
		 */

		attrs = getOrgUnitAttributes("groups");
		final DirContext groups = ctx.createSubcontext("ou=groups", attrs);

		attrs = getGroupAttributes(
				"uid=hnelson,ou=users,dc=example,dc=com", "dummy ldap role",
				"dummy_ldap");
		groups.createSubcontext("cn=dummy_ldap", attrs);

		attrs = getGroupAttributes(
				"uid=nelsonh,ou=users,dc=example,dc=com", "dummy ssl ldap role",
				"dummy_sslldap");
		groups.createSubcontext("cn=dummy_sslldap", attrs);
	}

	/**
	 * Convenience method for creating principals.
	 * 
	 * @param cn
	 *            the commonName of the person
	 * @param principal
	 *            the kerberos principal name for the person
	 * @param sn
	 *            the surName of the person
	 * @param uid
	 *            the unique identifier for the person
	 * @param userPassword
	 *            the credentials of the person
	 * @return the attributes of the person principal
	 */
	protected Attributes getPrincipalAttributes(final String sn,
			final String cn, final String uid, final String userPassword,
			final String principal) {
		final Attributes attrs = new BasicAttributes(true);
		final Attribute ocls = new BasicAttribute("objectClass");
		ocls.add("top");
		ocls.add("person"); // sn $ cn
		ocls.add("inetOrgPerson"); // uid
		ocls.add("krb5principal");
		ocls.add("krb5kdcentry");
		attrs.put(ocls);
		attrs.put("cn", cn);
		attrs.put("sn", sn);
		attrs.put("uid", uid);
		attrs.put("userPassword", userPassword);
		attrs.put("krb5PrincipalName", principal);
		attrs.put("krb5KeyVersionNumber", "0");

		return attrs;
	}

	protected Attributes getGroupAttributes(final String member,
			final String description, final String cn) {
		/*
		 * dn: cn=itpeople,ou=groups,dc=example,dc=com objectclass: groupofnames
		 * cn: itpeople description: IT security group member: cn=William
		 * Smith,ou=people,dc=example,dc=com
		 */

		final Attributes attrs = new BasicAttributes(true);
		final Attribute ocls = new BasicAttribute("objectClass");
		ocls.add("groupofnames");
		attrs.put(ocls);
		attrs.put("cn", cn);
		attrs.put("description", description);
		attrs.put("member", member);

		return attrs;
	}

	/**
	 * Convenience method for creating an organizational unit.
	 * 
	 * @param ou
	 *            the ou of the organizationalUnit
	 * @return the attributes of the organizationalUnit
	 */
	protected Attributes getOrgUnitAttributes(final String ou) {
		final Attributes attrs = new BasicAttributes(true);
		final Attribute ocls = new BasicAttribute("objectClass");
		ocls.add("top");
		ocls.add("organizationalUnit");
		attrs.put(ocls);
		attrs.put("ou", ou);

		return attrs;
	}

	protected void setContexts(final String user, final String passwd)
			throws Exception {
		final Hashtable<String, Object> env = new Hashtable<String, Object>();
		env.put(DirectoryService.JNDI_KEY, getService());
		env.put(Context.SECURITY_PRINCIPAL, user);
		env.put(Context.SECURITY_CREDENTIALS, passwd);
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		env.put(Context.INITIAL_CONTEXT_FACTORY,
				CoreContextFactory.class.getName());
		this.setContexts(env);
	}

	/**
	 * Sets the contexts of this class taking into account the extras and
	 * overrides properties.
	 * 
	 * @param env
	 *            an environment to use while setting up the system root.
	 * @throws NamingException
	 *             if there is a failure of any kind
	 */
	protected void setContexts(final Hashtable<String, Object> env)
			throws Exception {
		final Hashtable<String, Object> envFinal = new Hashtable<String, Object>(
				env);
		envFinal.put(Context.PROVIDER_URL, ServerDNConstants.SYSTEM_DN);
		sysRoot = new InitialLdapContext(envFinal, null);

		envFinal.put(Context.PROVIDER_URL, "");
		rootDse = getService().getAdminSession();

		envFinal.put(Context.PROVIDER_URL, SchemaConstants.OU_SCHEMA);
		schemaRoot = new InitialLdapContext(envFinal, null);
	}
	/*
	private class CallbackHandlerBean implements CallbackHandler {
		private final String name;
		private final String password;


		public CallbackHandlerBean(final String name, final String password) {
			this.name = name;
			this.password = password;
		}

		@Override
		public void handle(final Callback[] callbacks)
				throws UnsupportedCallbackException, IOException {
			for (int ii = 0; ii < callbacks.length; ii++) {
				final Callback callBack = callbacks[ii];

				// Handles username callback.
				if (callBack instanceof NameCallback) {
					final NameCallback nameCallback = (NameCallback) callBack;
					nameCallback.setName(this.name);
					// Handles password callback.
				} else if (callBack instanceof PasswordCallback) {
					final PasswordCallback passwordCallback = (PasswordCallback) callBack;
					passwordCallback.setPassword(this.password.toCharArray());
				} else {
					throw new UnsupportedCallbackException(callBack,
							I18n.err(I18n.ERR_617));
				}
			}
		}
	}*/
}
