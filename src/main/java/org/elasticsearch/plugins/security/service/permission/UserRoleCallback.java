package org.elasticsearch.plugins.security.service.permission;

public interface UserRoleCallback {

	public String getRemoteuser();

	public boolean isRemoteUserInRole(String role);

}
