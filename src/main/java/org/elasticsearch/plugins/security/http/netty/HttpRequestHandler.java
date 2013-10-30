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

import org.elasticsearch.common.netty.channel.ChannelHandler;
import org.elasticsearch.common.netty.channel.ChannelHandlerContext;
import org.elasticsearch.common.netty.channel.ExceptionEvent;
import org.elasticsearch.common.netty.channel.MessageEvent;
import org.elasticsearch.common.netty.channel.SimpleChannelUpstreamHandler;
import org.elasticsearch.common.netty.handler.codec.http.HttpRequest;

/**
 *
 */
@ChannelHandler.Sharable
public class HttpRequestHandler extends SimpleChannelUpstreamHandler {

	private final NettyHttpServerTransport serverTransport;

	public HttpRequestHandler(final NettyHttpServerTransport serverTransport) {
		this.serverTransport = serverTransport;
	}

	@Override
	public void messageReceived(final ChannelHandlerContext ctx,
			final MessageEvent e) throws Exception {
		final HttpRequest request = (HttpRequest) e.getMessage();
		// the netty HTTP handling always copy over the buffer to its own
		// buffer, either in NioWorker internally
		// when reading, or using a cumulation buffer
		this.serverTransport.dispatchRequest(
				new NettyHttpRequest(request, e.getChannel()),
				new NettyHttpChannel(this.serverTransport, e.getChannel(),
						request));
		super.messageReceived(ctx, e);
	}

	@Override
	public void exceptionCaught(final ChannelHandlerContext ctx,
			final ExceptionEvent e) throws Exception {
		this.serverTransport.exceptionCaught(ctx, e);
	}
}
