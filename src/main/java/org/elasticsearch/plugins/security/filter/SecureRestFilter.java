package org.elasticsearch.plugins.security.filter;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerRestChannel;
import org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerRestRequest;
import org.elasticsearch.plugins.security.service.SecurityService;
import org.elasticsearch.plugins.security.util.SecurityUtil;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestFilter;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

public abstract class SecureRestFilter extends RestFilter {

	protected final ESLogger log = Loggers.getLogger(this.getClass());

	protected SecurityService securityService;

	protected SecureRestFilter(final SecurityService securityService) {
		super();
		this.securityService = securityService;
	}

	protected InetAddress getClientHostAddress(final RestRequest request)
			throws UnknownHostException {

		final InetAddress hostAddress = this.securityService
				.getHostAddressFromRequest(request);

		return hostAddress;
	}

	@Override
	public final void process(final RestRequest request,
			final RestChannel channel, final RestFilterChain filterChain) {

		// TODO check aliases, multiple indices, _all, ...
		final List<String> indices = SecurityUtil.getIndices(request);
		if (indices.contains(this.securityService
				.getSecurityConfigurationIndex())) {

			try {
				if (this.getClientHostAddress(request).getHostAddress()
						.equals("127.0.0.1")) {
					filterChain.continueProcessing(request, channel);
				} else {
					SecurityUtil.send(request, channel, RestStatus.FORBIDDEN,
							"Only allowed from localhost");
				}
			} catch (final UnknownHostException e) {
				SecurityUtil.send(request, channel,
						RestStatus.INTERNAL_SERVER_ERROR, e.toString());
			}
		} else {

			((TomcatHttpServerRestRequest) request).getUserRoles();

			this.processSecure((TomcatHttpServerRestRequest) request,
					(TomcatHttpServerRestChannel) channel, filterChain);

		}

	}

	protected abstract void processSecure(
			final TomcatHttpServerRestRequest request,
			final TomcatHttpServerRestChannel channel,
			final RestFilterChain filterChain);

	protected abstract String getType();

	protected abstract String getId();
}
