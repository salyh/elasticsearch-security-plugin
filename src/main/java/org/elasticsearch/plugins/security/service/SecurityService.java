package org.elasticsearch.plugins.security.service;

import org.elasticsearch.ElasticSearchException;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugins.security.filter.ActionPathFilter;
import org.elasticsearch.plugins.security.filter.FieldResponseFilter;
import org.elasticsearch.rest.RestController;

public class SecurityService extends
		AbstractLifecycleComponent<SecurityService> {

	private final static String DEFAULT_SECURITY_CONFIG_INDEX = "securityconfiguration";
	private final String securityConfigurationIndex;
	private final RestController restController;
	private final Client client;

	@Inject
	public SecurityService(final Settings settings, final Client client,
			final RestController restController) {
		super(settings);

		this.restController = restController;
		this.client = client;
		this.securityConfigurationIndex = settings.get(
				"security.configuration.index", DEFAULT_SECURITY_CONFIG_INDEX);

	}

	@Override
	protected void doStart() throws ElasticSearchException {

		this.restController.registerFilter(new ActionPathFilter(this));
		this.restController.registerFilter(new FieldResponseFilter(this));
		this.logger.debug("security.configuration.index="
				+ this.securityConfigurationIndex);

		// TODO disable dynamic scripting for this node
		// https://github.com/yakaz/elasticsearch-action-reloadsettings/blob/master/src/main/java/org/elasticsearch/action/reloadsettings/ESInternalSettingsPerparer.java
		// client.execute(action, request)

	}

	@Override
	protected void doStop() throws ElasticSearchException {

		this.logger.debug("doStop");
	}

	@Override
	protected void doClose() throws ElasticSearchException {
		this.logger.debug("doClose())");

	}

	public String getXContentConfiguration(final String type, final String id) {
		return this.client
				.prepareGet(this.securityConfigurationIndex, type, id)
				.setRefresh(true).get().getSourceAsString();
	}

	public String getSecurityConfigurationIndex() {
		return this.securityConfigurationIndex;
	}

}
