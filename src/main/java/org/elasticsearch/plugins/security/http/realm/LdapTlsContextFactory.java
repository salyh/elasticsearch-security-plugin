package org.elasticsearch.plugins.security.http.realm;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import javax.naming.spi.InitialContextFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import com.sun.jndi.ldap.LdapCtxFactory;

public class LdapTlsContextFactory implements InitialContextFactory {

	private static final class ProxyLdapContext implements InvocationHandler {
		private final LdapContext delegate;
		private final StartTlsResponse tls;

		
		private ProxyLdapContext(Hashtable env) throws NamingException {
			final Map<String, Object> savedEnv = new HashMap<String, Object>();
			for (final String key : Arrays.asList(Context.SECURITY_AUTHENTICATION,
					Context.SECURITY_CREDENTIALS, Context.SECURITY_PRINCIPAL,
					Context.SECURITY_PROTOCOL)) {
				final Object entry = env.remove(key);
				if (entry != null) {
					savedEnv.put(key, entry);
				}
			}
			delegate = new InitialLdapContext(env, null);
			tls = (StartTlsResponse) delegate
					.extendedOperation(new StartTlsRequest());
			tls.setHostnameVerifier(new HostnameVerifier() {

				@Override
				public boolean verify(String hostname, SSLSession session) {
					return true;
				}
			});
			try {
				final SSLSession negotiate = tls.negotiate();
				Logger.getLogger(this.getClass().getCanonicalName()).fine(
						"LDAP is now using " + negotiate.getProtocol());
			} catch (final IOException e) {
				throw new NamingException(e.getMessage());
			}
			for (final Map.Entry<String, Object> savedEntry : savedEnv.entrySet()) {
				delegate.addToEnvironment(savedEntry.getKey(), savedEntry
						.getValue());
			}
		}

		@Override
		public Object invoke(Object proxy, Method method, Object[] args)
				throws Throwable {
			if ("close".equals(method.getName())) {
				return doClose(delegate);
			}
			return method.invoke(delegate, args);
		}

		private Object doClose(LdapContext delegate) throws IOException,
		IllegalAccessException, InvocationTargetException {
			try {
				if (tls != null) {
					try {
						tls.close();
					} catch (final IOException e) {
						throw new InvocationTargetException(e);
					}
				}
			} finally {
				try {
					if (delegate != null) {
						delegate.close();
					}
				} catch (final NamingException e) {
					throw new InvocationTargetException(e);
				}
			}
			return null;
		}
	}

	public static final String REAL_INITIAL_CONTEXT_FACTORY = "REAL_INITIAL_CONTEXT_FACTORY";

	@SuppressWarnings("unchecked")
	@Override
	public Context getInitialContext(final Hashtable environment)
			throws NamingException {
		final Hashtable proxyEnv = new Hashtable(environment);
		Object realFactory;
		if (environment.contains(REAL_INITIAL_CONTEXT_FACTORY)) {
			realFactory = environment.get(REAL_INITIAL_CONTEXT_FACTORY);
		} else {
			realFactory = LdapCtxFactory.class.getCanonicalName();
		}
		proxyEnv.put(Context.INITIAL_CONTEXT_FACTORY, realFactory);
		proxyEnv.put("com.sun.jndi.ldap.connect.pool", "false");
		return (Context) Proxy.newProxyInstance(this.getClass()
				.getClassLoader(), new Class<?>[] { DirContext.class },
				new ProxyLdapContext(proxyEnv));
	}

}
