package org.elasticsearch.plugins.security.http.tomcat;

import java.io.IOException;

import net.sf.michaelo.tomcat.realm.ActiveDirectoryRealm;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.SecurityConstraint;

public class FixedActiveDirectoryRealm extends ActiveDirectoryRealm {

	@Override
	public boolean hasResourcePermission(final Request request,
			final Response response, final SecurityConstraint[] constraints,
			final Context context) throws IOException {
		// TODO Auto-generated method stub
		return request.getPrincipal() != null;
	}
}
