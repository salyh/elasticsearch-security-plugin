package org.elasticsearch.plugins.security.waffle;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import waffle.mock.MockWindowsAuthProvider;
import waffle.servlet.spi.SecurityFilterProvider;
import waffle.windows.auth.IWindowsAuthProvider;
import waffle.windows.auth.IWindowsIdentity;

public class TestProvider implements SecurityFilterProvider {

	private MockWindowsAuthProvider _auth = null;

	public TestProvider(final IWindowsAuthProvider auth) {
		_auth = new MockWindowsAuthProvider();
		// System.out.println("ctor()");

	}

	@Override
	public void sendUnauthorized(final HttpServletResponse response) {
		// TODO Auto-generated method stub
		// System.out.println("sendUnauthorized()");
	}

	@Override
	public boolean isPrincipalException(final HttpServletRequest request) {
		// System.out.println("isPrincipalException()");
		return false;
	}

	@Override
	public IWindowsIdentity doFilter(final HttpServletRequest request,
			final HttpServletResponse response) throws IOException {
		// TODO Auto-generated method stub
		// System.out.println("auth guest");
		return _auth.logonUser("Guest", "");
	}

	@Override
	public boolean isSecurityPackageSupported(final String securityPackage) {
		// System.out.println("support " + securityPackage);
		return true;
	}

	@Override
	public void initParameter(final String parameterName,
			final String parameterValue) {
		// TODO Auto-generated method stub
		// System.out.println("init " + parameterName + "=" + parameterValue);
	}

}
