package org.elasticsearch.plugins.security.http.tomcat;

import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.realm.GenericPrincipal;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.Streams;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.http.HttpRequest;

import org.elasticsearch.rest.support.RestUtils;

import waffle.servlet.WindowsPrincipal;

public class TomcatHttpServerRestRequest extends 
HttpRequest {

	protected static final ESLogger log = Loggers
			.getLogger(TomcatHttpServerRestRequest.class);

	public static final String REQUEST_CONTENT_ATTRIBUTE = "org.elasticsearch.plugins.security.http.tomcat.request-content";

	private final HttpServletRequest request;

	private final Method method;

	private final Map<String, String> params;

	private BytesReference content;

	private final String opaqueId;

	public TomcatHttpServerRestRequest(final HttpServletRequest request)
			throws IOException {
		this.request = request;
		opaqueId = request.getHeader("X-Opaque-Id");
		method = Method.valueOf(request.getMethod());
		params = new HashMap<String, String>();

		log.debug("HttpServletRequest impl class: " + request.getClass());
		log.debug("HttpServletRequest ru: " + request.getRemoteUser());
		log.debug("HttpServletRequest up: " + request.getUserPrincipal());
		//log.debug("HttpServletRequest up: " + request.getUserPrincipal().getClass().toString());

		if (request.getQueryString() != null) {
			RestUtils.decodeQueryString(request.getQueryString(), 0,
					params);
		}

		content = new BytesArray(Streams.copyToByteArray(request
				.getInputStream()));
		request.setAttribute(REQUEST_CONTENT_ATTRIBUTE, content);
	}

	@Override
	public Method method() {
		return method;
	}

	@Override
	public String uri() {

		return request.getRequestURI();

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
		return uri();
	}

	@Override
	public boolean hasContent() {
		return content.length() > 0;
	}

	@Override
	public boolean contentUnsafe() {
		return false;
	}

	@Override
	public BytesReference content() {
		return content;
	}

	@Override
	public String header(final String name) {
		return request.getHeader(name);
	}

	@Override
	public Map<String, String> params() {
		return params;
	}

	@Override
	public boolean hasParam(final String key) {
		return params.containsKey(key);
	}

	@Override
	public String param(final String key) {
		return params.get(key);
	}

	@Override
	public String param(final String key, final String defaultValue) {
		final String value = params.get(key);
		if (value == null) {
			return defaultValue;
		}
		return value;
	}

	public String localAddr() {
		return request.getLocalAddr();
	}

	public long localPort() {
		return request.getLocalPort();
	}

	public String remoteAddr() {
		return request.getRemoteAddr();
	}

	public long remotePort() {
		return request.getRemotePort();
	}

	public String remoteUser() {
		return request.getRemoteUser();
	}

	public String scheme() {
		return request.getScheme();
	}

	public String contentType() {
		return request.getContentType();
	}

	public String opaqueId() {
		return opaqueId;
	}

	public HttpServletRequest getHttpServletRequest() {
		return request;

	}

	public Principal getUserPrincipal() {
		return request.getUserPrincipal();

	}

	public boolean isUserInRole(final String role) {
		return request.isUserInRole(role);

	}

	public List<String> getUserRoles() {

		if (request.getUserPrincipal() instanceof GenericPrincipal) {
			final GenericPrincipal wp = (GenericPrincipal) request
					.getUserPrincipal();

			if (wp.getRoles() != null) {
				final List<String> roles = Arrays.asList(wp.getRoles());
				log.debug("GenericPrincipal roles: " + roles);
				return roles;
			}
		}


		if (request.getUserPrincipal() instanceof WindowsPrincipal) {
			final WindowsPrincipal wp = (WindowsPrincipal) request
					.getUserPrincipal();

			log.debug("WindowsPrincipal roles: " + wp.getRolesString());
			log.debug("WindowsPrincipal groups: " + wp.getGroups());

			if (wp.getRolesString() != null) {
				return Arrays.asList(wp.getRolesString().split(","));
			}
		}

		/*if (this.request.getUserPrincipal() instanceof ActiveDirectoryPrincipal) {
			final ActiveDirectoryPrincipal ap = (ActiveDirectoryPrincipal) this.request
					.getUserPrincipal();

			log.debug("ActiveDirectoryPrincipal roles: " + ap.getRoles());

			return ap.getRoles();
		}*/

		return null;

	}

	@Override
	public Iterable<Entry<String, String>> headers() {
		
		Map<String, String> headerMap = new HashMap<String, String>(); 
		
		 while(request.getHeaderNames().hasMoreElements())
		 {
			 String headerName = request.getHeaderNames().nextElement();
			 headerMap.put(headerName, request.getHeader(headerName));
		 }
		 
		 return headerMap.entrySet();
	}


	//next three methods contributed by Ram Kotamaraja
	
	/**
	 * Setter Method for content
	 */
	 public void setContent(BytesReference content) {
		 this.content = content;
	 }

	 /**
	 * Getter Method for returning content
	 * @return BytesReference 
	 */
	 public BytesReference getContent() {
	 		return content;
	 }
	 
	 /**
	 * Method added to modify the request query based on the authorization permission settings 
	 * in the security configuration. This method will set the modified content in request.
	 * @param requestContentAttribute
	 * @param content
	 */
	 public void setAttribute(String requestContentAttribute,
			BytesReference content) {
	 		this.request.setAttribute(requestContentAttribute, content);
	 		
	 }
}
