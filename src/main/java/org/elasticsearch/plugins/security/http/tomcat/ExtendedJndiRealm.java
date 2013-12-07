package org.elasticsearch.plugins.security.http.tomcat;

import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.realm.JNDIRealm;
import org.apache.commons.lang.StringUtils;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

public class ExtendedJndiRealm extends JNDIRealm {

	private static final Log log = LogFactory.getLog(ExtendedJndiRealm.class);
	private final String sslUserAttribute;
	public ExtendedJndiRealm(String sslUserAttribute) {
		this.sslUserAttribute=sslUserAttribute;
	}

	@Override
	public boolean hasResourcePermission(Request request, Response response,
			SecurityConstraint[] constraints,
			org.apache.catalina.Context context) throws IOException {
		// TODO Auto-generated method stub
		return request.getPrincipal() != null;
	}

	/**
	 * Return the Principal associated with the given certificate.
	 */
	@Override
	protected Principal getPrincipal(X509Certificate usercert) {
		final String username = x509UsernameRetriever.getUsername(usercert);

		if(log.isDebugEnabled()) {
			log.debug(sm.getString("realmBase.gotX509Username", username));
		}


		if(sslUserAttribute != null && !sslUserAttribute.isEmpty()) {
			return getPrincipal(StringUtils.substringBetween(username, sslUserAttribute+"=",",")); //TODO fix case
		} else {
			return super.getPrincipal(username);
		}
	}


}
