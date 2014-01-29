package org.elasticsearch.plugins.security.http.realm;

import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;

import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.realm.RealmBase;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;

public class AllPermsRealm extends RealmBase {

	private static final ESLogger log = Loggers.getLogger(AllPermsRealm.class);
	
	public AllPermsRealm() {
		// TODO Auto-generated constructor stub
	}

	@Override
	protected String getName() {
		// TODO Auto-generated method stub
		return "AllPermsRealm";
	}



	@Override
	public Principal authenticate(GSSContext gssContext, boolean storeCred) {
		// TODO Auto-generated method stub

		log.debug("gssContext "+gssContext+storeCred);
		try {
			log.debug("gssContext "+gssContext.getSrcName().toString());
			log.debug("gssContext isinitiator "+gssContext.isInitiator());
		} catch (final GSSException e1) {
			// TODO Auto-generated catch block
			log.debug(e1.toString());
			//System.out.println(e1.toString());
		}
		log.debug("gssContext isEstablished "+gssContext.isEstablished());
		log.debug("gssContext getCredDelegState "+gssContext.getCredDelegState());				
		try {
			log.debug("gssContext "+gssContext.getDelegCred());
		} catch (final GSSException e) {
			// TODO Auto-generated catch block
			log.debug(e.toString());
		}

		return super.authenticate(gssContext, storeCred);
	}

	@Override
	protected Principal getPrincipal(String username,
			GSSCredential gssCredential) {

		log.debug("getPrincipal(String username, GSSCredential gssCredential) "+username+"//"+gssCredential);
		throw new RuntimeException(username+"//"+gssCredential);
	}

	@Override
	protected String getPassword(String username) {
		log.debug("getPassword "+username);
		return null;
	}

	@Override
	protected Principal getPrincipal(String username) {
		// TODO Auto-generated method stub
		log.debug("getPrincipal(String username) "+username);
		return new GenericPrincipal(username, null, Arrays.asList( "*".split("")));
	}

	@Override
	public boolean hasResourcePermission(Request request, Response response,
			SecurityConstraint[] constraints, Context context)
					throws IOException {
		// TODO Auto-generated method stub
		return request.getPrincipal() != null;
	}

	@Override
	public boolean hasRole(Wrapper wrapper, Principal principal, String role) {
		// TODO Auto-generated method stub
		return principal != null;
	}



}
