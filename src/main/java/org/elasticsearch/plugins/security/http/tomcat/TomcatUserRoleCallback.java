package org.elasticsearch.plugins.security.http.tomcat;

import javax.servlet.http.HttpServletRequest;

import org.elasticsearch.plugins.security.service.permission.UserRoleCallback;

public class TomcatUserRoleCallback implements UserRoleCallback {

	private final HttpServletRequest request;

	public TomcatUserRoleCallback(final HttpServletRequest request) {
		this.request = request;
	}

	@Override
	public String getRemoteuser() {

		return this.request.getRemoteUser();
	}

	@Override
	public boolean isRemoteUserInRole(final String role) {

		return this.request.isUserInRole(role);
	}

}
