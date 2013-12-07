package org.elasticsearch.plugins.security.filter;

import java.util.Arrays;

import org.elasticsearch.plugins.security.MalformedConfigurationException;
import org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerRestChannel;
import org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerRestRequest;
import org.elasticsearch.plugins.security.http.tomcat.TomcatUserRoleCallback;
import org.elasticsearch.plugins.security.service.SecurityService;
import org.elasticsearch.plugins.security.util.SecurityUtil;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestStatus;

public class ActionPathFilter extends SecureRestFilter {

	public ActionPathFilter(final SecurityService securityService) {
		super(securityService);

	}

	@Override
	public void processSecure(final TomcatHttpServerRestRequest request,
			final TomcatHttpServerRestChannel channel,
			final RestFilterChain filterChain) {

		if (SecurityUtil.stringContainsItemFromListAsTypeOrIndex(
				request.path(), SecurityUtil.BUILT_IN_ADMIN_COMMANDS)) {
			log.warn("Index- or Typename should not contains admin commands like "
					+ Arrays.toString(SecurityUtil.BUILT_IN_ADMIN_COMMANDS));
		}

		if (SecurityUtil.stringContainsItemFromListAsTypeOrIndex(
				request.path(), SecurityUtil.BUILT_IN_READ_COMMANDS)) {
			log.warn("Index- or Typename should not contains search commands like "
					+ Arrays.toString(SecurityUtil.BUILT_IN_READ_COMMANDS));
		}

		if (SecurityUtil.stringContainsItemFromListAsTypeOrIndex(
				request.path(), SecurityUtil.BUILT_IN_WRITE_COMMANDS)) {
			log.warn("Index- or Typename should not contains write commands like "
					+ Arrays.toString(SecurityUtil.BUILT_IN_WRITE_COMMANDS));
		}

		try {

			final PermLevel permLevel = new PermLevelEvaluator(
					securityService.getXContentSecurityConfiguration(
							getType(), getId()))
			.evaluatePerm(
					SecurityUtil.getIndices(request),
					SecurityUtil.getTypes(request),
					getClientHostAddress(request),
					new TomcatUserRoleCallback(request
							.getHttpServletRequest(),securityService.getSettings().get("security.ssl.userattribute")));

			if (permLevel == PermLevel.NONE) {
				SecurityUtil.send(request, channel, RestStatus.FORBIDDEN,
						"No permission (at all)");
				return;
			}

			if (permLevel.ordinal() < PermLevel.ALL.ordinal()
					&& SecurityUtil.isAdminRequest(request)) {
				SecurityUtil.send(request, channel, RestStatus.FORBIDDEN,
						"No permission (for admin actions)");
				return;
			}

			if (permLevel.ordinal() < PermLevel.READWRITE.ordinal()
					&& SecurityUtil.isWriteRequest(request)) {
				SecurityUtil.send(request, channel, RestStatus.FORBIDDEN,
						"No permission (for write actions)");
				return;
			}

			if (permLevel == PermLevel.READONLY
					&& !SecurityUtil.isReadRequest(request)) {
				SecurityUtil.send(request, channel, RestStatus.FORBIDDEN,
						"No permission (for read actions)");
				return;
			}

			filterChain.continueProcessing(request, channel);
			return;
		} catch (final MalformedConfigurationException e) {
			log.error("Cannot parse security configuration ", e);
			SecurityUtil.send(request, channel,
					RestStatus.INTERNAL_SERVER_ERROR,
					"Cannot parse security configuration");

			return;
		} catch (final Exception e) {
			log.error("Generic error: ", e);
			SecurityUtil.send(request, channel,
					RestStatus.INTERNAL_SERVER_ERROR,
					"Generic error, see log for details");

			return;
		}

	}

	@Override
	protected String getType() {

		return "actionpathfilter";
	}

	@Override
	protected String getId() {

		return "actionpathfilter";
	}

}
