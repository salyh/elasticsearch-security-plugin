/*
 * Licensed to ElasticSearch and Shay Banon under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. ElasticSearch licenses this
 * file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.plugins.security.http.netty;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.bytes.ChannelBufferBytesReference;
import org.elasticsearch.common.netty.channel.Channel;
import org.elasticsearch.common.netty.handler.codec.http.HttpMethod;
import org.elasticsearch.rest.support.AbstractRestRequest;
import org.elasticsearch.rest.support.RestUtils;

/**
 *
 */
public class NettyHttpRequest extends AbstractRestRequest implements
		org.elasticsearch.plugins.security.http.HttpRequest {

	private final org.elasticsearch.common.netty.handler.codec.http.HttpRequest request;

	private final Map<String, String> params;

	private final String rawPath;

	private final BytesReference content;

	private final String opaqueId;

	private final InetSocketAddress remoteAddress;

	private final InetSocketAddress localAddress;

	public NettyHttpRequest(
			final org.elasticsearch.common.netty.handler.codec.http.HttpRequest request,
			final Channel channel) {
		this.request = request;
		this.opaqueId = request.getHeader("X-Opaque-Id");
		this.remoteAddress = (InetSocketAddress) channel.getRemoteAddress();
		this.localAddress = (InetSocketAddress) channel.getLocalAddress();
		this.params = new HashMap<String, String>();
		if (request.getContent().readable()) {
			this.content = new ChannelBufferBytesReference(request.getContent());
		} else {
			this.content = BytesArray.EMPTY;
		}

		final String uri = request.getUri();
		final int pathEndPos = uri.indexOf('?');
		if (pathEndPos < 0) {
			this.rawPath = uri;
		} else {
			this.rawPath = uri.substring(0, pathEndPos);
			RestUtils.decodeQueryString(uri, pathEndPos + 1, this.params);
		}
	}

	@Override
	public Method method() {
		final HttpMethod httpMethod = this.request.getMethod();
		if (httpMethod == HttpMethod.GET) {
			return Method.GET;
		}

		if (httpMethod == HttpMethod.POST) {
			return Method.POST;
		}

		if (httpMethod == HttpMethod.PUT) {
			return Method.PUT;
		}

		if (httpMethod == HttpMethod.DELETE) {
			return Method.DELETE;
		}

		if (httpMethod == HttpMethod.HEAD) {
			return Method.HEAD;
		}

		if (httpMethod == HttpMethod.OPTIONS) {
			return Method.OPTIONS;
		}

		return Method.GET;
	}

	@Override
	public String uri() {
		return this.request.getUri();
	}

	@Override
	public String rawPath() {
		return this.rawPath;
	}

	@Override
	public Map<String, String> params() {
		return this.params;
	}

	@Override
	public boolean hasContent() {
		return this.content.length() > 0;
	}

	@Override
	public boolean contentUnsafe() {
		// Netty http decoder always copies over the http content
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

	@Override
	public String localAddr() {
		return this.localAddress.getAddress().getHostAddress();
	}

	@Override
	public long localPort() {
		return this.localAddress.getPort();
	}

	@Override
	public String remoteAddr() {

		return this.remoteAddress.getAddress().getHostAddress();
	}

	@Override
	public long remotePort() {
		return this.remoteAddress.getPort();
	}

	@Override
	public String opaqueId() {
		return this.opaqueId;
	}
}
