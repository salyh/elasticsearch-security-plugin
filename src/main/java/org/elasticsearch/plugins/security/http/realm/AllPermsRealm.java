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
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;

public class AllPermsRealm extends RealmBase {

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

		System.out.println("gssContext "+gssContext+storeCred);
		try {
			System.out.println("gssContext "+gssContext.getSrcName().toString());
			System.out.println("gssContext isinitiator "+gssContext.isInitiator());
		} catch (final GSSException e1) {
			// TODO Auto-generated catch block
			System.out.println(e1.toString());
		}
		System.out.println("gssContext isEstablished "+gssContext.isEstablished());
		System.out.println("gssContext getCredDelegState "+gssContext.getCredDelegState());
		try {
			System.out.println("gssContext "+gssContext.getDelegCred());
		} catch (final GSSException e) {
			// TODO Auto-generated catch block
			System.out.println(e.toString());
		}

		return super.authenticate(gssContext, storeCred);
	}

	@Override
	protected Principal getPrincipal(String username,
			GSSCredential gssCredential) {

		System.out.println("getPrincipal(String username, GSSCredential gssCredential) "+username+"//"+gssCredential);
		throw new RuntimeException(username+"//"+gssCredential);
	}

	@Override
	protected String getPassword(String username) {
		System.out.println("getPassword "+username);
		return null;
	}

	@Override
	protected Principal getPrincipal(String username) {
		// TODO Auto-generated method stub
		System.out.println("getPrincipal(String username) "+username);
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
