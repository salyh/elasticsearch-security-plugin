package org.elasticsearch.plugins.security.http.tomcat;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;

import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.common.xcontent.support.XContentMapValues;
import org.elasticsearch.http.HttpChannel;
import org.elasticsearch.plugins.security.MalformedConfigurationException;
import org.elasticsearch.plugins.security.filter.PermDlsEvaluator;
import org.elasticsearch.plugins.security.service.SecurityService;
import org.elasticsearch.plugins.security.service.permission.DlsPermission;
import org.elasticsearch.plugins.security.util.SecurityUtil;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.XContentRestResponse;

public class TomcatHttpServerRestChannel implements HttpChannel {

	protected final ESLogger log = Loggers.getLogger(this.getClass());

	private final TomcatHttpServerRestRequest restRequest;

	private final HttpServletResponse resp;

	private Exception sendFailure;

	private final CountDownLatch latch;

	private final SecurityService securityService;

	final Boolean enableDls;

	public TomcatHttpServerRestChannel(
			final TomcatHttpServerRestRequest restRequest,
			final HttpServletResponse resp,
			final SecurityService securityService) {
		this.securityService = securityService;
		this.restRequest = restRequest;
		this.resp = resp;
		this.latch = new CountDownLatch(1);

		this.enableDls = securityService.getSettings().getAsBoolean(
				"security.module.dls.enabled", true);

	}

	public void await() throws InterruptedException {
		this.latch.await();
	}

	public Exception sendFailure() {
		return this.sendFailure;
	}

	@Override
	public void sendResponse(final RestResponse response) {

		this.resp.setContentType(response.contentType());
		this.resp.addHeader("Access-Control-Allow-Origin", "*");
		if (response.status() != null) {
			this.resp.setStatus(response.status().getStatus());
		} else {
			this.resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		}
		if (this.restRequest.method() == RestRequest.Method.OPTIONS) {
			// also add more access control parameters
			this.resp.addHeader("Access-Control-Max-Age", "1728000");
			this.resp.addHeader("Access-Control-Allow-Methods", "PUT, DELETE");
			this.resp.addHeader("Access-Control-Allow-Headers",
					"X-Requested-With");
		}
		try {

			final XContentBuilder modifiedContent = this.enableDls ? this
					.applyDls(response) : ((XContentRestResponse) response)
					.builder();

			int contentLength = modifiedContent.bytes().length();
			if (response.prefixContentLength() > 0) {
				contentLength += response.prefixContentLength();
			}
			if (response.suffixContentLength() > 0) {
				contentLength += response.suffixContentLength();
			}

			this.resp.setContentLength(contentLength);

			final ServletOutputStream out = this.resp.getOutputStream();
			if (response.prefixContent() != null) {

				out.write(response.prefixContent(), 0,
						response.prefixContentLength());
			}

			out.write(modifiedContent.bytes().toBytes(), 0, modifiedContent
					.bytes().length());

			if (response.suffixContent() != null) {

				out.write(response.suffixContent(), 0,
						response.suffixContentLength());
			}
			out.close();
		} catch (final Exception e) {
			this.log.error(e.toString(), e);
			this.sendFailure = e;
		} finally {
			this.latch.countDown();
		}
	}

	protected XContentBuilder applyDls(final RestResponse response)
			throws IOException, MalformedConfigurationException {

		final XContentRestResponse xres = (XContentRestResponse) response;

		final List<String> indices = SecurityUtil.getIndices(this.restRequest);
		if (indices.contains(this.securityService
				.getSecurityConfigurationIndex())) {

			if (this.securityService
					.getHostAddressFromRequest(this.restRequest)
					.getHostAddress().equals("127.0.0.1")) {
				return xres.builder();

			} else {
				throw new IOException("Only allowed from localhost");
			}

		}

		if (response.status().getStatus() < 200
				|| response.status().getStatus() >= 300) {

			return xres.builder();
		}

		if (!this.restRequest.path().contains("_search")
				&& !this.restRequest.path().contains("_msearch")) {

			return xres.builder();
		}

		final List<String> dlsTokens = new PermDlsEvaluator(
				this.securityService.getXContentSecurityConfiguration(
						"dlspermissions", "dlspermissions")).evaluatePerm(
				SecurityUtil.getIndices(this.restRequest),
				SecurityUtil.getTypes(this.restRequest),
				this.securityService
						.getHostAddressFromRequest(this.restRequest),
				new TomcatUserRoleCallback(this.restRequest
						.getHttpServletRequest()));

		this.log.debug("dls tokens: " + dlsTokens);

		// this.log.debug("orig json: " + xres.builder().string());

		final List<DlsPermission> perms = this.securityService
				.parseDlsPermissions(xres.builder().bytes());

		// TODO check against the tokens

		final Tuple<XContentType, Map<String, Object>> mapTuple = XContentHelper
				.convertToMap(xres.builder().bytes().toBytes(), true);

		final List<String> fields = new ArrayList<String>();
		fields.add("_shards*");
		fields.add("took");
		fields.add("timed_out");
		fields.add("hits.total");
		fields.add("hits.max_score");
		fields.add("hits.hits._index");
		fields.add("hits.hits._type");
		fields.add("hits.hits._id");
		fields.add("hits.hits._score");

		for (final DlsPermission p : perms) {

			if (p.isAnyTokenAllowedToRead(dlsTokens)) {

				fields.add("hits.hits._source." + p.getField());

			}

		}

		this.log.debug(fields.toString());

		final Map<String, Object> filteredSource = XContentMapValues.filter(
				mapTuple.v2(), fields.toArray(new String[0]), null);

		this.log.debug("filteredSource " + filteredSource);

		final XContentBuilder sourceToBeReturned = XContentFactory
				.contentBuilder(mapTuple.v1()).map(filteredSource);
		return sourceToBeReturned;

	}

}
