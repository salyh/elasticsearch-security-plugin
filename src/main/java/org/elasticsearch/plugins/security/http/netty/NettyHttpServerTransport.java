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

import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_BLOCKING;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_BLOCKING_SERVER;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_DEFAULT_RECEIVE_BUFFER_SIZE;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_DEFAULT_SEND_BUFFER_SIZE;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_KEEP_ALIVE;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_NO_DELAY;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_RECEIVE_BUFFER_SIZE;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_REUSE_ADDRESS;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_SEND_BUFFER_SIZE;
import static org.elasticsearch.common.util.concurrent.EsExecutors.daemonThreadFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import org.elasticsearch.ElasticSearchException;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.netty.NettyStaticSetup;
import org.elasticsearch.common.netty.OpenChannelsHandler;
import org.elasticsearch.common.netty.bootstrap.ServerBootstrap;
import org.elasticsearch.common.netty.channel.AdaptiveReceiveBufferSizePredictorFactory;
import org.elasticsearch.common.netty.channel.Channel;
import org.elasticsearch.common.netty.channel.ChannelHandlerContext;
import org.elasticsearch.common.netty.channel.ChannelPipeline;
import org.elasticsearch.common.netty.channel.ChannelPipelineFactory;
import org.elasticsearch.common.netty.channel.Channels;
import org.elasticsearch.common.netty.channel.ExceptionEvent;
import org.elasticsearch.common.netty.channel.FixedReceiveBufferSizePredictorFactory;
import org.elasticsearch.common.netty.channel.ReceiveBufferSizePredictorFactory;
import org.elasticsearch.common.netty.channel.socket.nio.NioServerSocketChannelFactory;
import org.elasticsearch.common.netty.channel.socket.oio.OioServerSocketChannelFactory;
import org.elasticsearch.common.netty.handler.codec.http.HttpChunkAggregator;
import org.elasticsearch.common.netty.handler.codec.http.HttpContentCompressor;
import org.elasticsearch.common.netty.handler.codec.http.HttpContentDecompressor;
import org.elasticsearch.common.netty.handler.codec.http.HttpRequestDecoder;
import org.elasticsearch.common.netty.handler.codec.http.HttpResponseEncoder;
import org.elasticsearch.common.netty.handler.timeout.ReadTimeoutException;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.network.NetworkUtils;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.BoundTransportAddress;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.common.transport.NetworkExceptionHelper;
import org.elasticsearch.common.transport.PortsRange;
import org.elasticsearch.common.unit.ByteSizeUnit;
import org.elasticsearch.common.unit.ByteSizeValue;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.http.BindHttpException;
import org.elasticsearch.http.HttpChannel;
import org.elasticsearch.http.HttpInfo;
import org.elasticsearch.http.HttpRequest;
import org.elasticsearch.http.HttpServerAdapter;
import org.elasticsearch.http.HttpServerTransport;
import org.elasticsearch.http.HttpStats;
import org.elasticsearch.monitor.jvm.JvmInfo;
import org.elasticsearch.transport.BindTransportException;

/**
 *
 */
public class NettyHttpServerTransport extends
		AbstractLifecycleComponent<HttpServerTransport> implements
		HttpServerTransport {

	static {
		NettyStaticSetup.setup();
	}

	private final NetworkService networkService;

	final ByteSizeValue maxContentLength;
	final ByteSizeValue maxInitialLineLength;
	final ByteSizeValue maxHeaderSize;
	final ByteSizeValue maxChunkSize;

	private final int workerCount;

	private final boolean blockingServer;

	final boolean compression;

	private final int compressionLevel;

	final boolean resetCookies;

	private final String port;

	private final String bindHost;

	private final String publishHost;

	private final Boolean tcpNoDelay;

	private final Boolean tcpKeepAlive;

	private final Boolean reuseAddress;

	private final ByteSizeValue tcpSendBufferSize;
	private final ByteSizeValue tcpReceiveBufferSize;
	private final ReceiveBufferSizePredictorFactory receiveBufferSizePredictorFactory;

	final ByteSizeValue maxCumulationBufferCapacity;
	final int maxCompositeBufferComponents;

	private volatile ServerBootstrap serverBootstrap;

	private volatile BoundTransportAddress boundAddress;

	private volatile Channel serverChannel;

	OpenChannelsHandler serverOpenChannels;

	private volatile HttpServerAdapter httpServerAdapter;

	@Inject
	public NettyHttpServerTransport(final Settings settings,
			final NetworkService networkService) {
		super(settings);

		this.networkService = networkService;

		if (settings.getAsBoolean("netty.epollBugWorkaround", false)) {
			System.setProperty("org.jboss.netty.epollBugWorkaround", "true");
		}

		ByteSizeValue maxContentLength = this.componentSettings.getAsBytesSize(
				"max_content_length", settings.getAsBytesSize(
						"http.max_content_length", new ByteSizeValue(100,
								ByteSizeUnit.MB)));
		this.maxChunkSize = this.componentSettings.getAsBytesSize(
				"max_chunk_size", settings.getAsBytesSize(
						"http.max_chunk_size", new ByteSizeValue(8,
								ByteSizeUnit.KB)));
		this.maxHeaderSize = this.componentSettings.getAsBytesSize(
				"max_header_size", settings.getAsBytesSize(
						"http.max_header_size", new ByteSizeValue(8,
								ByteSizeUnit.KB)));
		this.maxInitialLineLength = this.componentSettings.getAsBytesSize(
				"max_initial_line_length", settings.getAsBytesSize(
						"http.max_initial_line_length", new ByteSizeValue(4,
								ByteSizeUnit.KB)));
		// don't reset cookies by default, since I don't think we really need to
		// note, parsing cookies was fixed in netty 3.5.1 regarding stack
		// allocation, but still, currently, we don't need cookies
		this.resetCookies = this.componentSettings.getAsBoolean(
				"reset_cookies",
				settings.getAsBoolean("http.reset_cookies", false));
		this.maxCumulationBufferCapacity = this.componentSettings
				.getAsBytesSize("max_cumulation_buffer_capacity", null);
		this.maxCompositeBufferComponents = this.componentSettings.getAsInt(
				"max_composite_buffer_components", -1);
		this.workerCount = this.componentSettings.getAsInt("worker_count",
				EsExecutors.boundedNumberOfProcessors(settings) * 2);
		this.blockingServer = settings.getAsBoolean(
				"http.blocking_server",
				settings.getAsBoolean(TCP_BLOCKING_SERVER,
						settings.getAsBoolean(TCP_BLOCKING, false)));
		this.port = this.componentSettings.get("port",
				settings.get("http.port", "9200-9300"));
		this.bindHost = this.componentSettings.get("bind_host",
				settings.get("http.bind_host", settings.get("http.host")));
		this.publishHost = this.componentSettings.get("publish_host",
				settings.get("http.publish_host", settings.get("http.host")));
		this.tcpNoDelay = this.componentSettings.getAsBoolean("tcp_no_delay",
				settings.getAsBoolean(TCP_NO_DELAY, true));
		this.tcpKeepAlive = this.componentSettings.getAsBoolean(
				"tcp_keep_alive", settings.getAsBoolean(TCP_KEEP_ALIVE, true));
		this.reuseAddress = this.componentSettings.getAsBoolean(
				"reuse_address",
				settings.getAsBoolean(TCP_REUSE_ADDRESS,
						NetworkUtils.defaultReuseAddress()));
		this.tcpSendBufferSize = this.componentSettings.getAsBytesSize(
				"tcp_send_buffer_size", settings.getAsBytesSize(
						TCP_SEND_BUFFER_SIZE, TCP_DEFAULT_SEND_BUFFER_SIZE));
		this.tcpReceiveBufferSize = this.componentSettings.getAsBytesSize(
				"tcp_receive_buffer_size", settings.getAsBytesSize(
						TCP_RECEIVE_BUFFER_SIZE,
						TCP_DEFAULT_RECEIVE_BUFFER_SIZE));

		long defaultReceiverPredictor = 512 * 1024;
		if (JvmInfo.jvmInfo().mem().directMemoryMax().bytes() > 0) {
			// we can guess a better default...
			final long l = (long) (0.3 * JvmInfo.jvmInfo().mem()
					.directMemoryMax().bytes() / this.workerCount);
			defaultReceiverPredictor = Math.min(defaultReceiverPredictor,
					Math.max(l, 64 * 1024));
		}

		// See AdaptiveReceiveBufferSizePredictor#DEFAULT_XXX for default values
		// in netty..., we can use higher ones for us, even fixed one
		final ByteSizeValue receivePredictorMin = this.componentSettings
				.getAsBytesSize("receive_predictor_min", this.componentSettings
						.getAsBytesSize("receive_predictor_size",
								new ByteSizeValue(defaultReceiverPredictor)));
		final ByteSizeValue receivePredictorMax = this.componentSettings
				.getAsBytesSize("receive_predictor_max", this.componentSettings
						.getAsBytesSize("receive_predictor_size",
								new ByteSizeValue(defaultReceiverPredictor)));
		if (receivePredictorMax.bytes() == receivePredictorMin.bytes()) {
			this.receiveBufferSizePredictorFactory = new FixedReceiveBufferSizePredictorFactory(
					(int) receivePredictorMax.bytes());
		} else {
			this.receiveBufferSizePredictorFactory = new AdaptiveReceiveBufferSizePredictorFactory(
					(int) receivePredictorMin.bytes(),
					(int) receivePredictorMin.bytes(),
					(int) receivePredictorMax.bytes());
		}

		this.compression = settings.getAsBoolean("http.compression", false);
		this.compressionLevel = settings.getAsInt("http.compression_level", 6);

		// validate max content length
		if (maxContentLength.bytes() > Integer.MAX_VALUE) {
			this.logger.warn("maxContentLength[" + maxContentLength
					+ "] set to high value, resetting it to [100mb]");
			maxContentLength = new ByteSizeValue(100, ByteSizeUnit.MB);
		}
		this.maxContentLength = maxContentLength;

		this.logger
				.debug("using max_chunk_size[{}], max_header_size[{}], max_initial_line_length[{}], max_content_length[{}], receive_predictor[{}->{}]",
						this.maxChunkSize, this.maxHeaderSize,
						this.maxInitialLineLength, this.maxContentLength,
						receivePredictorMin, receivePredictorMax);

		this.logger.debug("loaded secure transport");

	}

	public Settings settings() {
		return this.settings;
	}

	@Override
	public void httpServerAdapter(final HttpServerAdapter httpServerAdapter) {
		this.httpServerAdapter = httpServerAdapter;
	}

	@Override
	protected void doStart() throws ElasticSearchException {
		this.serverOpenChannels = new OpenChannelsHandler(this.logger);

		if (this.blockingServer) {
			this.serverBootstrap = new ServerBootstrap(
					new OioServerSocketChannelFactory(
							Executors.newCachedThreadPool(daemonThreadFactory(
									this.settings, "http_server_boss")),
							Executors.newCachedThreadPool(daemonThreadFactory(
									this.settings, "http_server_worker"))));
		} else {
			this.serverBootstrap = new ServerBootstrap(
					new NioServerSocketChannelFactory(
							Executors.newCachedThreadPool(daemonThreadFactory(
									this.settings, "http_server_boss")),
							Executors.newCachedThreadPool(daemonThreadFactory(
									this.settings, "http_server_worker")),
							this.workerCount));
		}

		this.serverBootstrap.setPipelineFactory(new MyChannelPipelineFactory(
				this));

		if (this.tcpNoDelay != null) {
			this.serverBootstrap.setOption("child.tcpNoDelay", this.tcpNoDelay);
		}
		if (this.tcpKeepAlive != null) {
			this.serverBootstrap
					.setOption("child.keepAlive", this.tcpKeepAlive);
		}
		if (this.tcpSendBufferSize != null
				&& this.tcpSendBufferSize.bytes() > 0) {
			this.serverBootstrap.setOption("child.sendBufferSize",
					this.tcpSendBufferSize.bytes());
		}
		if (this.tcpReceiveBufferSize != null
				&& this.tcpReceiveBufferSize.bytes() > 0) {
			this.serverBootstrap.setOption("child.receiveBufferSize",
					this.tcpReceiveBufferSize.bytes());
		}
		this.serverBootstrap.setOption("receiveBufferSizePredictorFactory",
				this.receiveBufferSizePredictorFactory);
		this.serverBootstrap.setOption(
				"child.receiveBufferSizePredictorFactory",
				this.receiveBufferSizePredictorFactory);
		if (this.reuseAddress != null) {
			this.serverBootstrap.setOption("reuseAddress", this.reuseAddress);
			this.serverBootstrap.setOption("child.reuseAddress",
					this.reuseAddress);
		}

		// Bind and start to accept incoming connections.
		InetAddress hostAddressX;
		try {
			hostAddressX = this.networkService
					.resolveBindHostAddress(this.bindHost);
		} catch (final IOException e) {
			throw new BindHttpException("Failed to resolve host ["
					+ this.bindHost + "]", e);
		}
		final InetAddress hostAddress = hostAddressX;

		final PortsRange portsRange = new PortsRange(this.port);
		final AtomicReference<Exception> lastException = new AtomicReference<Exception>();
		final boolean success = portsRange
				.iterate(new PortsRange.PortCallback() {
					@Override
					public boolean onPortNumber(final int portNumber) {
						try {
							NettyHttpServerTransport.this.serverChannel = NettyHttpServerTransport.this.serverBootstrap
									.bind(new InetSocketAddress(hostAddress,
											portNumber));
						} catch (final Exception e) {
							lastException.set(e);
							return false;
						}
						return true;
					}
				});
		if (!success) {
			throw new BindHttpException(
					"Failed to bind to [" + this.port + "]",
					lastException.get());
		}

		final InetSocketAddress boundAddress = (InetSocketAddress) this.serverChannel
				.getLocalAddress();
		InetSocketAddress publishAddress;
		try {
			publishAddress = new InetSocketAddress(
					this.networkService
							.resolvePublishHostAddress(this.publishHost),
					boundAddress.getPort());
		} catch (final Exception e) {
			throw new BindTransportException(
					"Failed to resolve publish address", e);
		}
		this.boundAddress = new BoundTransportAddress(
				new InetSocketTransportAddress(boundAddress),
				new InetSocketTransportAddress(publishAddress));
	}

	@Override
	protected void doStop() throws ElasticSearchException {
		if (this.serverChannel != null) {
			this.serverChannel.close().awaitUninterruptibly();
			this.serverChannel = null;
		}

		if (this.serverOpenChannels != null) {
			this.serverOpenChannels.close();
			this.serverOpenChannels = null;
		}

		if (this.serverBootstrap != null) {
			this.serverBootstrap.releaseExternalResources();
			this.serverBootstrap = null;
		}
	}

	@Override
	protected void doClose() throws ElasticSearchException {
	}

	@Override
	public BoundTransportAddress boundAddress() {
		return this.boundAddress;
	}

	@Override
	public HttpInfo info() {
		return new HttpInfo(this.boundAddress(), this.maxContentLength.bytes());
	}

	@Override
	public HttpStats stats() {
		final OpenChannelsHandler channels = this.serverOpenChannels;
		return new HttpStats(channels == null ? 0
				: channels.numberOfOpenChannels(), channels == null ? 0
				: channels.totalChannels());
	}

	void dispatchRequest(final HttpRequest request, final HttpChannel channel) {
		this.httpServerAdapter.dispatchRequest(request, channel);
	}

	void exceptionCaught(final ChannelHandlerContext ctx, final ExceptionEvent e)
			throws Exception {
		if (e.getCause() instanceof ReadTimeoutException) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Connection timeout [{}]", ctx.getChannel()
						.getRemoteAddress());
			}
			ctx.getChannel().close();
		} else {
			if (!this.lifecycle.started()) {
				// ignore
				return;
			}
			if (!NetworkExceptionHelper
					.isCloseConnectionException(e.getCause())) {
				this.logger
						.warn("Caught exception while handling client http traffic, closing connection {}",
								e.getCause(), ctx.getChannel());
				ctx.getChannel().close();
			} else {
				this.logger
						.debug("Caught exception while handling client http traffic, closing connection {}",
								e.getCause(), ctx.getChannel());
				ctx.getChannel().close();
			}
		}
	}

	static class MyChannelPipelineFactory implements ChannelPipelineFactory {

		private final NettyHttpServerTransport transport;

		private final HttpRequestHandler requestHandler;

		MyChannelPipelineFactory(final NettyHttpServerTransport transport) {
			this.transport = transport;
			this.requestHandler = new HttpRequestHandler(transport);
		}

		@Override
		public ChannelPipeline getPipeline() throws Exception {
			final ChannelPipeline pipeline = Channels.pipeline();
			pipeline.addLast("openChannels", this.transport.serverOpenChannels);
			final HttpRequestDecoder requestDecoder = new HttpRequestDecoder(
					(int) this.transport.maxInitialLineLength.bytes(),
					(int) this.transport.maxHeaderSize.bytes(),
					(int) this.transport.maxChunkSize.bytes());
			if (this.transport.maxCumulationBufferCapacity != null) {
				if (this.transport.maxCumulationBufferCapacity.bytes() > Integer.MAX_VALUE) {
					requestDecoder
							.setMaxCumulationBufferCapacity(Integer.MAX_VALUE);
				} else {
					requestDecoder
							.setMaxCumulationBufferCapacity((int) this.transport.maxCumulationBufferCapacity
									.bytes());
				}
			}
			if (this.transport.maxCompositeBufferComponents != -1) {
				requestDecoder
						.setMaxCumulationBufferComponents(this.transport.maxCompositeBufferComponents);
			}
			pipeline.addLast("decoder", requestDecoder);
			if (this.transport.compression) {
				pipeline.addLast("decoder_compress",
						new HttpContentDecompressor());
			}
			final HttpChunkAggregator httpChunkAggregator = new HttpChunkAggregator(
					(int) this.transport.maxContentLength.bytes());
			if (this.transport.maxCompositeBufferComponents != -1) {
				httpChunkAggregator
						.setMaxCumulationBufferComponents(this.transport.maxCompositeBufferComponents);
			}
			pipeline.addLast("aggregator", httpChunkAggregator);
			pipeline.addLast("encoder", new HttpResponseEncoder());
			if (this.transport.compression) {
				pipeline.addLast("encoder_compress", new HttpContentCompressor(
						this.transport.compressionLevel));
			}
			pipeline.addLast("handler", this.requestHandler);
			return pipeline;
		}
	}
}
