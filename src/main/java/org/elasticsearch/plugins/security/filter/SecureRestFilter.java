package org.elasticsearch.plugins.security.filter;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

import org.elasticsearch.common.Strings;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.plugins.security.service.SecurityService;
import org.elasticsearch.plugins.security.util.SecurityUtil;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestFilter;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

public abstract class SecureRestFilter extends RestFilter {

	protected final ESLogger log = Loggers.getLogger(this.getClass());

	protected final String xForwardFor = "X-Forwarded-For";

	protected SecurityService securityService;

	protected SecureRestFilter(final SecurityService securityService) {
		super();
		this.securityService = securityService;
	}

	protected static String[] BUILT_IN_ADMIN_COMMANDS = new String[] {
			"_cluster", "_settings", "_close", "_open", "_template", "_status",
			"_stats", "_segments", "_cache", "_gateway", "_optimize", "_flush",
			"_warmer", "_refresh", "_cache", "_shutdown", "_nodes" };
	protected static String[] BUILT_IN_WRITE_COMMANDS = new String[] {
			"_update", "_bulk", "_mapping", "_aliases", "_analyze" };
	protected static String[] BUILT_IN_READ_COMMANDS = new String[] {
			"_search", "_msearch" };

	protected InetAddress getClientHostAddress(final RestRequest request)
			throws UnknownHostException {

		final InetAddress hostAddress = this.securityService
				.getHostAddressFromRequest(request);
		this.log.debug("Client IP: " + hostAddress);
		return hostAddress;
	}

	protected List<String> getIndices(final RestRequest request) {
		String[] indices = new String[0];
		final String path = request.path();

		this.log.info("Evaluate decoded path '" + path + "'");

		if (!path.startsWith("/")) {

			return null;
		}

		if (path.length() > 1) {

			int endIndex;

			if ((endIndex = path.indexOf('/', 1)) != -1) {
				indices = Strings.splitStringByCommaToArray(path.substring(1,
						endIndex));

			}
		}

		this.log.debug("Indices: " + Arrays.toString(indices));
		return Arrays.asList(indices);

	}

	@Override
	public final void process(final RestRequest request,
			final RestChannel channel, final RestFilterChain filterChain) {

		final List<String> indices = this.getIndices(request);
		if (indices.size() == 1
				&& indices.get(0).equals(
						this.securityService.getSecurityConfigurationIndex())) {

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
			this.processSecure(request, channel, filterChain);

		}

	}

	protected abstract void processSecure(final RestRequest request,
			final RestChannel channel, final RestFilterChain filterChain);

	protected abstract String getType();

	protected abstract String getId();
}
