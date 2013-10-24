package org.elasticsearch.plugins.security.filter;

import java.util.Arrays;

import org.elasticsearch.plugins.security.MalformedConfigurationException;
import org.elasticsearch.plugins.security.service.SecurityService;
import org.elasticsearch.plugins.security.util.SecurityUtil;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestStatus;

public class ActionPathFilter extends SecureRestFilter {

	public ActionPathFilter(final SecurityService securityService) {
		super(securityService);

	}

	private static boolean stringContainsItemFromListAsCommand(
			final String inputString, final String[] items) {
		for (int i = 0; i < items.length; i++) {
			if (inputString.contains("/" + items[i])
					&& !inputString.contains(items[i] + "/")) {
				return true;
			}
		}
		return false;
	}

	private static boolean stringContainsItemFromListAsTypeOrIndex(
			final String inputString, final String[] items) {
		for (int i = 0; i < items.length; i++) {
			if (inputString.contains("/" + items[i] + "/")) {
				return true;
			}
		}
		return false;
	}

	private boolean isWriteRequest(final RestRequest request) {
		if (request.method() == Method.DELETE || request.method() == Method.PUT) {
			return true;
		}

		if (request.method() == Method.POST) {
			if (!stringContainsItemFromListAsCommand(request.path(),
					BUILT_IN_READ_COMMANDS)) {
				return true;
			}
		}

		return stringContainsItemFromListAsCommand(request.path(),
				BUILT_IN_WRITE_COMMANDS);
	}

	private boolean isAdminRequest(final RestRequest request) {
		return stringContainsItemFromListAsCommand(request.path(),
				BUILT_IN_ADMIN_COMMANDS);
	}

	private boolean isReadRequest(final RestRequest request) {
		return !this.isWriteRequest(request) && !this.isAdminRequest(request);
	}

	@Override
	public void processSecure(final RestRequest request,
			final RestChannel channel, final RestFilterChain filterChain) {

		if (stringContainsItemFromListAsTypeOrIndex(request.path(),
				BUILT_IN_ADMIN_COMMANDS)) {
			this.log.warn("Index- or Typename should not contains admin commands like "
					+ Arrays.toString(BUILT_IN_ADMIN_COMMANDS));
		}

		if (stringContainsItemFromListAsTypeOrIndex(request.path(),
				BUILT_IN_READ_COMMANDS)) {
			this.log.warn("Index- or Typename should not contains search commands like "
					+ Arrays.toString(BUILT_IN_READ_COMMANDS));
		}

		if (stringContainsItemFromListAsTypeOrIndex(request.path(),
				BUILT_IN_WRITE_COMMANDS)) {
			this.log.warn("Index- or Typename should not contains write commands like "
					+ Arrays.toString(BUILT_IN_WRITE_COMMANDS));
		}

		try {

			final PermLevel permLevel = new PermLevelEvaluator(
					this.securityService.getXContentConfiguration(
							this.getType(), this.getId())).evaluatePerm(
					this.getIndices(request),
					this.getClientHostAddress(request));

			if (permLevel == PermLevel.NONE) {
				SecurityUtil.send(request, channel, RestStatus.FORBIDDEN,
						"No permission (at all)");
				return;
			}

			if (permLevel.ordinal() < PermLevel.ALL.ordinal()
					&& this.isAdminRequest(request)) {
				SecurityUtil.send(request, channel, RestStatus.FORBIDDEN,
						"No permission (for admin actions)");
				return;
			}

			if (permLevel.ordinal() < PermLevel.READWRITE.ordinal()
					&& this.isWriteRequest(request)) {
				SecurityUtil.send(request, channel, RestStatus.FORBIDDEN,
						"No permission (for write actions)");
				return;
			}

			if (permLevel == PermLevel.READONLY && !this.isReadRequest(request)) {
				SecurityUtil.send(request, channel, RestStatus.FORBIDDEN,
						"No permission (for read actions)");
				return;
			}

			filterChain.continueProcessing(request, channel);
			return;
		} catch (final MalformedConfigurationException e) {
			this.log.error("Cannot parse security configuration ", e);
			SecurityUtil.send(request, channel,
					RestStatus.INTERNAL_SERVER_ERROR,
					"Cannot parse security configuration");

			return;
		} catch (final Exception e) {
			this.log.error("Generic error: ", e);
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
