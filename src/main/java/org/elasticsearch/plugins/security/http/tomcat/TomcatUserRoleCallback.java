package org.elasticsearch.plugins.security.http.tomcat;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.elasticsearch.plugins.security.service.permission.UserRoleCallback;

public class TomcatUserRoleCallback implements UserRoleCallback {

	private final HttpServletRequest request;
	private final String sslUserAttribute;

	public TomcatUserRoleCallback(final HttpServletRequest request, String sslUserAttribute) {
		this.request = request;
		this.sslUserAttribute=sslUserAttribute;
	}

	@Override
	public String getRemoteuser() {


		String remoteUser = request.getRemoteUser();

		//CN=nelsonh, OU=marketingc, O=Saly Test Inc 2, DC=saly, DC=de
		if(remoteUser != null && !remoteUser.isEmpty())
		{
			if(sslUserAttribute != null && remoteUser.contains(sslUserAttribute))
			{
				remoteUser = StringUtils.substringBetween(remoteUser.toLowerCase(), //TODO fix lower case
						(sslUserAttribute+"=").toLowerCase(), ",");
			}
		}

		return remoteUser;
	}

	@Override
	public boolean isRemoteUserInRole(final String role) {

		return request.isUserInRole(role);
	}

}
