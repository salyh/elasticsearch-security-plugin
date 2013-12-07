package org.elasticsearch.plugins.security.util;

import java.util.Map;

import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.support.AbstractRestRequest;

public class EditableRestRequest extends AbstractRestRequest {

	private RestRequest innerRestquest = null;
	private BytesReference content = null;
	private Map<String, String> params = null;
	private Method method = null;
	private String uri = null;
	private String rawPath = null;
	private boolean hasContent;
	private boolean contentUnsafe;

	public EditableRestRequest(final RestRequest innerRestquest) {

		this.innerRestquest = innerRestquest;
		content = innerRestquest.content();
		params = innerRestquest.params();
		method = innerRestquest.method();
		uri = innerRestquest.uri();
		rawPath = innerRestquest.rawPath();
		hasContent = innerRestquest.hasContent();
		contentUnsafe = innerRestquest.contentUnsafe();

	}

	public void setContent(final BytesReference content) {
		this.content = content;
	}

	public void setParams(final Map<String, String> params) {
		this.params = params;
	}

	public void setMethod(final Method method) {
		this.method = method;
	}

	public void setUri(final String uri) {
		this.uri = uri;
	}

	public void setRawPath(final String rawPath) {
		this.rawPath = rawPath;
	}

	public void setHasContent(final boolean hasContent) {
		this.hasContent = hasContent;
	}

	public void setContentUnsafe(final boolean contentUnsafe) {
		this.contentUnsafe = contentUnsafe;
	}

	@Override
	public Method method() {
		return method;
	}

	@Override
	public String uri() {
		return uri;
	}

	@Override
	public String rawPath() {

		return rawPath;
	}

	@Override
	public boolean hasContent() {

		return hasContent;
	}

	@Override
	public boolean contentUnsafe() {

		return contentUnsafe;
	}

	@Override
	public BytesReference content() {

		return content;
	}

	@Override
	public String header(final String name) {

		return innerRestquest.header(name);
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
	public Map<String, String> params() {

		return params;
	}

	@Override
	public String param(final String key, final String defaultValue) {
		final String value = params.get(key);
		if (value == null) {
			return defaultValue;
		}
		return value;
	}

}
