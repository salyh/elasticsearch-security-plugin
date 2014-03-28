package org.elasticsearch.plugins.security.service;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import org.elasticsearch.ElasticSearchException;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.plugins.security.MalformedConfigurationException;
import org.elasticsearch.plugins.security.filter.ActionPathFilter;
import org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerRestRequest;
import org.elasticsearch.plugins.security.service.permission.DlsPermission;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;

import com.jayway.jsonpath.JsonPath;

public class SecurityService extends
AbstractLifecycleComponent<SecurityService> {

	public Settings getSettings() {
		return settings;
	}

	private final static String DEFAULT_SECURITY_CONFIG_INDEX = "securityconfiguration";
	private final String securityConfigurationIndex;
	private final RestController restController;
	private final Client client;
	private final Settings settings;
	private final boolean strictModeEnabled;

	@Inject
	public SecurityService(final Settings settings, final Client client,
			final RestController restController) {
		super(settings);

		this.settings = settings;
		this.restController = restController;
		this.client = client;
		securityConfigurationIndex = settings.get(
				"security.configuration.index", DEFAULT_SECURITY_CONFIG_INDEX);

		strictModeEnabled = settings.getAsBoolean(
				"security.strict", false);

	}

	public boolean isStrictModeEnabled() {
		return strictModeEnabled;
	}

	public Client getClient() {
		return client;
	}

	@Override
	protected void doStart() throws ElasticSearchException {

		// TODO order

		final Boolean enableActionPathFilter = settings.getAsBoolean(
				"security.module.actionpathfilter.enabled", true);

		if (enableActionPathFilter != null
				&& enableActionPathFilter.booleanValue()) {
			restController.registerFilter(new ActionPathFilter(this));
		}

		// this.restController
		// .registerFilter(new FieldLevelPermissionFilter(this));
		// this.restController.registerFilter(new FieldResponseFilter(this));

		// this.logger.debug("security.configuration.index="
		// + this.securityConfigurationIndex);

		// TODO disable dynamic scripting for this node
		// https://github.com/yakaz/elasticsearch-action-reloadsettings/blob/master/src/main/java/org/elasticsearch/action/reloadsettings/ESInternalSettingsPerparer.java
		// client.execute(action, request)

	}

	@Override
	protected void doStop() throws ElasticSearchException {

		logger.debug("doStop");
	}

	@Override
	protected void doClose() throws ElasticSearchException {
		logger.debug("doClose");

	}

	public String getXContentSecurityConfiguration(final String type,
			final String id) throws IOException,
			MalformedConfigurationException {
		try {
			return XContentHelper.convertToJson(
					getXContentSecurityConfigurationAsBR(type, id), true);
		} catch (final IOException e) {
			logger.error("Unable to load type {} and id {} due to {}",
					type, id, e);
			return null;
		}
	}

	public BytesReference getXContentSecurityConfigurationAsBR(
			final String type, final String id)
					throws MalformedConfigurationException {
		final GetResponse resp = client
				.prepareGet(securityConfigurationIndex, type, id)
				.setRefresh(true).get();

		if (resp.isExists()) {
			return resp.getSourceAsBytesRef();
		} else {
			throw new MalformedConfigurationException("document type " + type
					+ " with id " + id + " does not exists");
		}
	}

	public String getSecurityConfigurationIndex() {
		return securityConfigurationIndex;
	}

	public InetAddress getHostAddressFromRequest(final RestRequest request)
			throws UnknownHostException {

		// this.logger.debug(request.getClass().toString());

		final String oaddr = ((TomcatHttpServerRestRequest) request).remoteAddr();
		// this.logger.debug("original hostname: " + addr);

		String raddr = oaddr;

		if (oaddr == null || oaddr.isEmpty()) {
			throw new UnknownHostException("Original host is <null> or <empty>");
		}

		final InetAddress iaddr = InetAddress.getByName(oaddr);

		// security.http.xforwardfor.header
		// security.http.xforwardfor.trustedproxies
		// security.http.xforwardfor.enforce
		final String xForwardedForHeader = settings
				.get("security.http.xforwardedfor.header");

		if (xForwardedForHeader != null && !xForwardedForHeader.isEmpty()) {

			final String xForwardedForValue = request
					.header(xForwardedForHeader);

			logger.debug("xForwardedForHeader is " + xForwardedForHeader
					+ ":" + xForwardedForValue);

			final String xForwardedTrustedProxiesS = settings
					.get("security.http.xforwardedfor.trustedproxies");
			// TODO use yaml list
			final String[] xForwardedTrustedProxies = xForwardedTrustedProxiesS == null ? new String[0]
					: xForwardedTrustedProxiesS.replace(" ", "").split(",");

			final boolean xForwardedEnforce = settings.getAsBoolean(
					"security.http.xforwardedfor.enforce", false);

			if (xForwardedForValue != null && !xForwardedForValue.isEmpty()) {
				final List<String> addresses = Arrays.asList(xForwardedForValue
						.replace(" ", "").split(","));
				final List<String> proxiesPassed = new ArrayList<String>(
						addresses.subList(1, addresses.size()));

				if (xForwardedTrustedProxies.length == 0) {
					throw new UnknownHostException("No trusted proxies");
				}

				proxiesPassed
				.removeAll(Arrays.asList(xForwardedTrustedProxies));

				logger.debug(proxiesPassed.size() + "/" + proxiesPassed);

				if (proxiesPassed.size() == 0
						&& (Arrays.asList(xForwardedTrustedProxies).contains(
								oaddr) || iaddr.isLoopbackAddress())) {

					raddr = addresses.get(0).trim();

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

		if (raddr == null || raddr.isEmpty()) {
			throw new UnknownHostException("Host is <null> or <empty>");
		}

		if(raddr.equals(oaddr)) {
			return iaddr;
		} else {
			// if null or "" then loopback is returned
			return InetAddress.getByName(raddr);
		}

	}

	@SuppressWarnings("unchecked")
	public List<DlsPermission> parseDlsPermissions(final BytesReference br)
			throws IOException, MalformedConfigurationException {

		final List<DlsPermission> perms = new ArrayList<DlsPermission>();

		final List<JSONObject> dlsPermissions = new ArrayList<JSONObject>();

		String json = XContentHelper.convertToJson(br, false);

		if (json.contains("\"hits\":{\"total\":0,\"max_score\":null")) {
			// no hits
			logger.debug("No hits, return ALL permissions");
			perms.add(DlsPermission.ALL_PERMISSION);
			return perms;
		}

		if (!json.contains("dlspermissions")) {
			json = XContentHelper.convertToJson(getXContentSecurityConfigurationAsBR("dlspermissions",
					"default"), false);
		}

		if (json.contains("_source")) {
			dlsPermissions.addAll((List<JSONObject>) JsonPath.read(json,
					"$.hits.hits[*]._source.dlspermissions"));
		} else {
			dlsPermissions.add((JSONObject) JsonPath.read(json,
					"$.dlspermissions"));
		}

		for (final JSONObject dlsPermission : dlsPermissions) {

			if (dlsPermission == null) {
				continue;
			}

			for (final String field : dlsPermission.keySet()) {

				final DlsPermission dlsPerm = new DlsPermission();
				dlsPerm.setField(field);

				JSONArray ja = (JSONArray) ((JSONObject) dlsPermission
						.get(field)).get("read");
				dlsPerm.addReadTokens(ja.toArray(new String[0]));

				ja = (JSONArray) ((JSONObject) dlsPermission.get(field))
						.get("update");
				dlsPerm.addUpdateTokens(ja.toArray(new String[0]));

				ja = (JSONArray) ((JSONObject) dlsPermission.get(field))
						.get("delete");
				dlsPerm.addDeleteTokens(ja.toArray(new String[0]));

				perms.add(dlsPerm);
			}

		}

		return perms;

	}

}
