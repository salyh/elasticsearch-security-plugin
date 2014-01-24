package org.elasticsearch.plugins.security.filter;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.common.xcontent.support.XContentMapValues;
import org.elasticsearch.plugins.security.MalformedConfigurationException;
import org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerRestChannel;
import org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerRestRequest;
import org.elasticsearch.plugins.security.http.tomcat.TomcatUserRoleCallback;
import org.elasticsearch.plugins.security.service.SecurityService;
import org.elasticsearch.plugins.security.service.permission.DlsPermission;
import org.elasticsearch.plugins.security.util.EditableRestRequest;
import org.elasticsearch.plugins.security.util.SecurityUtil;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestStatus;

/**
 * NOT USED YET Protecting documents/fields from being updated or deletet on
 * dlstoken basis
 * 
 * @author salyh
 * 
 */
public class DlsWriteFilter extends SecureRestFilter {

	public DlsWriteFilter(final SecurityService securityService) {
		super(securityService);

	}

	@Override
	public void processSecure(final TomcatHttpServerRestRequest request,
			final TomcatHttpServerRestChannel channel,
			final RestFilterChain filterChain) {

		try {

			if (!SecurityUtil.isWriteRequest(request, securityService.isStrictModeEnabled())) {
				filterChain.continueProcessing(request, channel);
				return;
			}

			final List<String> dlsTokens = new PermDlsEvaluator(
					securityService.getXContentSecurityConfiguration(
							getType(), getId()))
			.evaluatePerm(
					SecurityUtil.getIndices(request),
					SecurityUtil.getTypes(request),
					getClientHostAddress(request),
					new TomcatUserRoleCallback(request
							.getHttpServletRequest(),securityService.getSettings().get("security.ssl.userattribute")));

			final String json = XContentHelper.convertToJson(request.content(),
					true);

			// TODO _bulk api

			// final XContentParser parser = XContentHelper.createParser(request
			// .content());

			log.debug("fieldlevelpermfilter orig: " + json);

			log.debug("dls tokens: " + dlsTokens);

			final String id = SecurityUtil.getId(request);

			try {
				final GetResponse res = securityService
						.getClient()
						.get(new GetRequest(SecurityUtil.getIndices(request)
								.get(0), SecurityUtil.getTypes(request).get(0),
								id)).actionGet();

				log.debug("document with id found: " + res.getId());

				final List<DlsPermission> perms = securityService
						.parseDlsPermissions(res.getSourceAsBytesRef());

				log.debug("perms " + perms);

				final List<String> fields = new ArrayList<String>();

				for (final DlsPermission p : perms) {

					if (p.isAnyTokenAllowedToUpdate(dlsTokens))

					{
						fields.add(p.getField());
					}

				}
				log.debug("ffields " + fields);

				final Tuple<XContentType, Map<String, Object>> mapTuple = XContentHelper
						.convertToMap(request.content(), true);

				final Map<String, Object> filteredSource = XContentMapValues
						.filter(mapTuple.v2(), fields.toArray(new String[0]),
								new String[] { "*" });

				log.debug("filteredSource " + filteredSource);

				final XContentBuilder sourceToBeReturned = XContentFactory
						.contentBuilder(mapTuple.v1()).map(filteredSource);

				final EditableRestRequest err = new EditableRestRequest(request);
				err.setContent(sourceToBeReturned.bytes());

				filterChain.continueProcessing(err, channel);
				return;

			} catch (final Exception e) {
				// TODO Auto-generated catch block
				// e.printStackTrace();
				log.debug("no document with id found: " + e.getMessage());
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

		return "dlspermissions";
	}

	@Override
	protected String getId() {

		return "dlspermissions";
	}

}
