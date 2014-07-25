package org.elasticsearch.plugins.security.filter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.plugins.security.MalformedConfigurationException;
import org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerRestChannel;
import org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerRestRequest;
import org.elasticsearch.plugins.security.http.tomcat.TomcatUserRoleCallback;
import org.elasticsearch.plugins.security.service.SecurityService;
import org.elasticsearch.plugins.security.util.EditableRestRequest;
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
				request.path(), securityService.isStrictModeEnabled()?SecurityUtil.BUILT_IN_READ_COMMANDS_STRICT : SecurityUtil.BUILT_IN_READ_COMMANDS_LAX)) {
			log.warn("Index- or Typename should not contains search commands like "
					+ Arrays.toString(securityService.isStrictModeEnabled()?SecurityUtil.BUILT_IN_READ_COMMANDS_STRICT : SecurityUtil.BUILT_IN_READ_COMMANDS_LAX));
		}

		if (SecurityUtil.stringContainsItemFromListAsTypeOrIndex(
				request.path(), securityService.isStrictModeEnabled()?SecurityUtil.BUILT_IN_WRITE_COMMANDS_STRICT : SecurityUtil.BUILT_IN_WRITE_COMMANDS_LAX)) {
			log.warn("Index- or Typename should not contains write commands like "
					+ Arrays.toString(securityService.isStrictModeEnabled()?SecurityUtil.BUILT_IN_WRITE_COMMANDS_STRICT : SecurityUtil.BUILT_IN_WRITE_COMMANDS_LAX));
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
					&& SecurityUtil.isWriteRequest(request,securityService.isStrictModeEnabled())) {
				SecurityUtil.send(request, channel, RestStatus.FORBIDDEN,
						"No permission (for write actions)");
				return;
			}

			if (permLevel == PermLevel.READONLY
					&& !SecurityUtil.isReadRequest(request,securityService.isStrictModeEnabled())) {
				SecurityUtil.send(request, channel, RestStatus.FORBIDDEN,
						"No permission (for read actions)");
				return;
			}
			
			// Ram Kotamarja - START
			// adding code to modify request modification before it hits elastic
			// search to apply the search filters
			modifiyKibanaRequest(request, channel);
			// Ram Kotamaraja - END
			

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
	
	/**
	 * Method added to modify the request on the fly to
	 * allow it to process generic queries coming from kibana by
	 * validating against the security framework (contributed by Ram Kotamaraja)
	 * @param request
	 */
	private void modifiyKibanaRequest(
			final TomcatHttpServerRestRequest request,
			final TomcatHttpServerRestChannel channel) {

		List<String> reqTypesList = SecurityUtil.getTypes(request);
		if (reqTypesList != null && !reqTypesList.isEmpty()
				&& reqTypesList.size() > 0) {
			// This means, there is a type specified in the request and so there
			// is not need to do anything as the framework will take care of the
			// type level security
			log.debug("Not modifying the request as there is one or more types already associated with the request");
			reqTypesList = null;
			return;
		}

		String kibanaPermLevel = null;
		try {
			kibanaPermLevel = securityService.getXContentSecurityConfiguration(
					getType(), getKibanaId());
		} catch (Exception e) {
			log.debug("No Kibana configuration found, so continuing the rest of the process: "+e.getMessage());
			return;
		}

		List<String> kibanaTypesList = null;
		List<String> authorizedTypesList = new ArrayList<String>();
		try {
			if (kibanaPermLevel != null && kibanaPermLevel.length() > 0) {
				kibanaTypesList = securityService.getKibanaTypes(SecurityUtil
						.getIndices(request));
			}

			final String reqContent = request.content().toUtf8();
			String modifiedContent = reqContent;

			// checking where the original request has any types
			List<String> requestTypes = SecurityUtil.getTypes(request);

			// If original request has any requests, then skip the logic below
			// as
			// permission evaluation has to be done based on that specific type
			if (requestTypes == null || requestTypes.isEmpty()
					|| requestTypes.size() == 0) {
				if (kibanaTypesList != null) {

					// determine authorized types list
					

					Iterator<String> kibanaTypesItr = kibanaTypesList
							.iterator();

					while (kibanaTypesItr.hasNext()) {

						List<String> kibanaType = new ArrayList<String>();
						kibanaType.add((String) kibanaTypesItr.next());
						final PermLevel permLevel = new PermLevelEvaluator(
								securityService
										.getXContentSecurityConfiguration(
												getType(), getId()))
								.evaluatePerm(
										SecurityUtil.getIndices(request),
										// SecurityUtil.getTypes(request),
										kibanaType,
										getClientHostAddress(request),
										new TomcatUserRoleCallback(
												request.getHttpServletRequest(),
												securityService
														.getSettings()
														.get("security.ssl.userattribute")));

						log.debug("Kibana perm level = "+permLevel);

						if (!permLevel.equals(PermLevel.NONE)) {
							authorizedTypesList.addAll(kibanaType);
						}
					}

					

					log.debug("Processing kibana types  "+ kibanaTypesList);
					log.debug("request Content =  "+ reqContent);

					String kibanaFilterStarter = "\"must\":[";
					int beginIndex = reqContent.indexOf(kibanaFilterStarter);
					
					if (beginIndex > 0) {
						String preReqContent = reqContent.substring(0,
								beginIndex + kibanaFilterStarter.length());
						String postReqContent = reqContent.substring(beginIndex
								+ kibanaFilterStarter.length());

						modifiedContent = preReqContent
								+ "{\"or\": {\"filters\":[";

						if (authorizedTypesList != null) {
							Iterator<String> authorizedTypesItr = authorizedTypesList
									.iterator();
							while (authorizedTypesItr.hasNext()) {
								modifiedContent += "{\"type\":{\"value\":\""
										+ authorizedTypesItr.next().toString()
										+ "\"}},";
							}
							modifiedContent = modifiedContent.substring(0,
									modifiedContent.length() - 1);
						}

						modifiedContent += "]}}," + postReqContent;
						log.debug("modified request content = " + modifiedContent);
												
						request.setContent(new BytesArray(modifiedContent));
						request.setAttribute(TomcatHttpServerRestRequest.REQUEST_CONTENT_ATTRIBUTE, request.getContent());

					}
				}
			}
		} catch (MalformedConfigurationException e) {
			log.error("Cannot parse security configuration ", e);
			SecurityUtil.send(request, channel,
					RestStatus.INTERNAL_SERVER_ERROR,
					"Cannot parse security configuration");

			return;
		} catch (Exception e) {
			log.error("Generic error: ", e);
			SecurityUtil.send(request, channel,
					RestStatus.INTERNAL_SERVER_ERROR,
					"Generic error, see log for details");

			return;
		}

	}

	/**
	 * Method to return the default id (contributed by Ram Kotamaraja)
	 * @return String - default id string
	 */
	 protected String getKibanaId() {
				return "kibana";
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
