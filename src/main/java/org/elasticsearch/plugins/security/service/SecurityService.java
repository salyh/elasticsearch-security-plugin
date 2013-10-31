package org.elasticsearch.plugins.security.service;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.elasticsearch.ElasticSearchException;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugins.security.filter.ActionPathFilter;
import org.elasticsearch.plugins.security.filter.FieldResponseFilter;
import org.elasticsearch.plugins.security.http.HttpRequest;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;

public class SecurityService extends
		AbstractLifecycleComponent<SecurityService> {

	private final static String DEFAULT_SECURITY_CONFIG_INDEX = "securityconfiguration";
	private final String securityConfigurationIndex;
	private final RestController restController;
	private final Client client;
	private final Settings settings;

	@Inject
	public SecurityService(final Settings settings, final Client client,
			final RestController restController) {
		super(settings);

		this.settings = settings;
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

	public InetAddress getHostAddressFromRequest(final RestRequest request)
			throws UnknownHostException {

		this.logger.debug(request.getClass().toString());

		String addr = ((HttpRequest) request).remoteAddr();

		this.logger.debug("original hostname: " + addr);

		if (addr == null || addr.isEmpty()) {
			throw new UnknownHostException("Original host is <null> or <empty>");
		}

		// security.http.xforwardfor.header
		// security.http.xforwardfor.trustedproxies
		// security.http.xforwardfor.enforce
		final String xForwardedForHeader = this.settings
				.get("security.http.xforwardedfor.header");

		if (xForwardedForHeader != null && !xForwardedForHeader.isEmpty()) {

			final String xForwardedForValue = request
					.header(xForwardedForHeader);
			final String xForwardedTrustedProxiesS = this.settings
					.get("security.http.xforwardedfor.trustedproxies");
			final String[] xForwardedTrustedProxies = xForwardedTrustedProxiesS == null ? new String[0]
					: xForwardedTrustedProxiesS.replace(" ", "").split(",");
			final boolean xForwardedEnforce = this.settings.getAsBoolean(
					"security.http.xforwardedfor.enforce", false);

			if (xForwardedForValue != null && !xForwardedForValue.isEmpty()) {
				final List<String> addresses = Arrays.asList(xForwardedForValue
						.replace(" ", "").split(","));
				final List<String> proxiesPassed = new ArrayList<String>(addresses.subList(1,
						addresses.size()));
				
				if(xForwardedTrustedProxies.length == 0)
				{
					throw new UnknownHostException(
							"No trusted proxies");					
				}
				
				proxiesPassed.removeAll(Arrays.asList(xForwardedTrustedProxies));

				logger.debug(proxiesPassed.size()+"/"+proxiesPassed);
				
				if (proxiesPassed.size()==0 && (Arrays.asList(xForwardedTrustedProxies).contains(addr) || "127.0.0.1".equals(addr))) {
								
					addr = addresses.get(0).trim();

				} else {
					throw new UnknownHostException(
							"Not all proxies are trusted");
				}

			} else {
				if (xForwardedEnforce) {
					throw new UnknownHostException(
							"Forward header enforced but not present");
				}
			}

		}

		if (addr == null || addr.isEmpty()) {
			throw new UnknownHostException("Host is <null> or <empty>");
		}

		// if null or "" then loopback is returned
		return InetAddress.getByName(addr);

	}

}
