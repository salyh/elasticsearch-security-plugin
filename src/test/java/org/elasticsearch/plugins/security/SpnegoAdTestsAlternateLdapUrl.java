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
public class SpnegoAdTestsAlternateLdapUrl extends SpnegoAdTests {

	
	@Override
	protected Properties getProperties() {
		final Properties props = new Properties();
		props.putAll(super.getProperties());
		props.setProperty("security.kerberos.mode", "spnegoad");
		props.setProperty("security.authorization.ldap.isactivedirectory", "false");
		props.setProperty("security.authorization.ldap.ldapurls", "ldap://dummy-non-existent:1234, ldap://localhost:6389");

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



	
}
