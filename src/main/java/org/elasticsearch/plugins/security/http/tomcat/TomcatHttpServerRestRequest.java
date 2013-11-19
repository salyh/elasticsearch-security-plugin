package org.elasticsearch.plugins.security.http.tomcat;

import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import net.sf.michaelo.tomcat.realm.ActiveDirectoryPrincipal;

import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.Streams;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.http.HttpRequest;
import org.elasticsearch.rest.support.AbstractRestRequest;
import org.elasticsearch.rest.support.RestUtils;

import waffle.servlet.WindowsPrincipal;

public class TomcatHttpServerRestRequest extends AbstractRestRequest implements
		HttpRequest {

	protected static final ESLogger log = Loggers
			.getLogger(TomcatHttpServerRestRequest.class);

	public static final String REQUEST_CONTENT_ATTRIBUTE = "org.elasticsearch.plugins.security.http.tomcat.request-content";

	private final HttpServletRequest request;

	private final Method method;

	private final Map<String, String> params;

	private final BytesReference content;

	private final String opaqueId;

	public TomcatHttpServerRestRequest(final HttpServletRequest request)
			throws IOException {
		this.request = request;
		this.opaqueId = request.getHeader("X-Opaque-Id");
		this.method = Method.valueOf(request.getMethod());
		this.params = new HashMap<String, String>();

		log.debug("HttpServletRequest impl class: " + request.getClass());

		if (request.getQueryString() != null) {
			RestUtils.decodeQueryString(request.getQueryString(), 0,
					this.params);
		}

		this.content = new BytesArray(Streams.copyToByteArray(request
				.getInputStream()));
		request.setAttribute(REQUEST_CONTENT_ATTRIBUTE, this.content);
	}

	@Override
	public Method method() {
		return this.method;
	}

	@Override
	public String uri() {

		return this.request.getRequestURI();

		/*
		 * int prefixLength = 0; if (request.getContextPath() != null ) {
		 * prefixLength += request.getContextPath().length(); } if
		 * (request.getServletPath() != null ) { prefixLength +=
		 * request.getServletPath().length(); } if (prefixLength > 0) { return
		 * request.getRequestURI().substring(prefixLength); } else { return
		 * request.getRequestURI(); }
		 */
	}

	@Override
	public String rawPath() {
		return this.uri();
	}

	@Override
	public boolean hasContent() {
		return this.content.length() > 0;
	}

	@Override
	public boolean contentUnsafe() {
		return false;
	}

	@Override
	public BytesReference content() {
		return this.content;
	}

	@Override
	public String header(final String name) {
		return this.request.getHeader(name);
	}

	@Override
	public Map<String, String> params() {
		return this.params;
	}

	@Override
	public boolean hasParam(final String key) {
		return this.params.containsKey(key);
	}

	@Override
	public String param(final String key) {
		return this.params.get(key);
	}

	@Override
	public String param(final String key, final String defaultValue) {
		final String value = this.params.get(key);
		if (value == null) {
			return defaultValue;
		}
		return value;
	}

	public String localAddr() {
		return this.request.getLocalAddr();
	}

	public long localPort() {
		return this.request.getLocalPort();
	}

	public String remoteAddr() {
		return this.request.getRemoteAddr();
	}

	public long remotePort() {
		return this.request.getRemotePort();
	}

	public String remoteUser() {
		return this.request.getRemoteUser();
	}

	public String scheme() {
		return this.request.getScheme();
	}

	public String contentType() {
		return this.request.getContentType();
	}

	public String opaqueId() {
		return this.opaqueId;
	}

	public HttpServletRequest getHttpServletRequest() {
		return this.request;

	}

	public Principal getUserPrincipal() {
		return this.request.getUserPrincipal();

	}

	public boolean isUserInRole(final String role) {
		return this.request.isUserInRole(role);

	}

	public List<String> getUserRoles() {

		if (this.request.getUserPrincipal() instanceof WindowsPrincipal) {
			final WindowsPrincipal wp = (WindowsPrincipal) this.request
					.getUserPrincipal();

			log.debug("WindowsPrincipal roles: " + wp.getRolesString());
			log.debug("WindowsPrincipal groups: " + wp.getGroups());

			if (wp.getRolesString() != null) {
				return Arrays.asList(wp.getRolesString().split(","));
			}
		}

		if (this.request.getUserPrincipal() instanceof ActiveDirectoryPrincipal) {
			final ActiveDirectoryPrincipal ap = (ActiveDirectoryPrincipal) this.request
					.getUserPrincipal();

			log.debug("ActiveDirectoryPrincipal roles: " + ap.getRoles());

			return ap.getRoles();
		}

		return null;

	}

}
