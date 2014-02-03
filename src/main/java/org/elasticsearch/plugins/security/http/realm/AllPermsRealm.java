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
import org.ietf.jgss.GSSCredential;

public class AllPermsRealm extends RealmBase {

	@Override
	protected String getName() {
		return "AllPermsRealm";
	}


	@Override
	protected Principal getPrincipal(String username,
			GSSCredential gssCredential) {

		throw new RuntimeException(username+"//"+gssCredential);
	}

	@Override
	protected String getPassword(String username) {
		return null;
	}

	@Override
	protected Principal getPrincipal(String username) {
		return new GenericPrincipal(username, null, Arrays.asList( "*".split("")));
	}

	@Override
	public boolean hasResourcePermission(Request request, Response response,
			SecurityConstraint[] constraints, Context context)
					throws IOException {

		return request.getPrincipal() != null;
	}

	@Override
	public boolean hasRole(Wrapper wrapper, Principal principal, String role) {

		return principal != null;
	}


}
