package org.elasticsearch.plugins.security.http.tomcat;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;

import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.xcontent.XContent;
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
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestResponse;

public class TomcatHttpServerRestChannel extends HttpChannel {

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
		super(restRequest);
		this.securityService = securityService;
		this.restRequest = restRequest;
		this.resp = resp;
		latch = new CountDownLatch(1);

		enableDls = securityService.getSettings().getAsBoolean(
				"security.module.dls.enabled", true);

	}

	public void await() throws InterruptedException {
		latch.await();
	}

	public Exception sendFailure() {
		return sendFailure;
	}

	@Override
	public void sendResponse(final RestResponse response) {

		resp.setContentType(response.contentType());
		resp.addHeader("Access-Control-Allow-Origin", "*");
		if (response.status() != null) {
			resp.setStatus(response.status().getStatus());
		} else {
			resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		}
		if (restRequest.method() == RestRequest.Method.OPTIONS) {
			// TODO: also add more access control parameters
			resp.addHeader("Access-Control-Max-Age", "1728000");
			
			//@author - Ram Kotamaraja
			//enhancing the list of allowed method list to meet the requirements of Kibana
			resp.addHeader("Access-Control-Allow-Methods", "OPTIONS, HEAD, GET, POST, PUT, DELETE");
			resp.addHeader("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Content-Length");
		}
		try {

			log.debug("RestResponse class " +response.getClass());
			
			if(enableDls) {
				BytesReference modifiedContent = applyDls((BytesRestResponse)response);				
				int contentLength = modifiedContent.length();
				resp.setContentLength(contentLength);
				final ServletOutputStream out = resp.getOutputStream();
				modifiedContent.writeTo(out);
				out.close();
			
			} else {
				int contentLength = response.content().length();
				resp.setContentLength(contentLength);
	            ServletOutputStream out = resp.getOutputStream();
	            response.content().writeTo(out);
                out.close();
			}
			


			
		} catch (final Exception e) {
			log.error(e.toString(), e);
			sendFailure = e;
		} finally {
			latch.countDown();
		}
	}

	protected BytesReference applyDls(final BytesRestResponse xres)
			throws IOException, MalformedConfigurationException {


		final List<String> indices = SecurityUtil.getIndices(restRequest);
		if (indices.contains(securityService
				.getSecurityConfigurationIndex())) {

			if (securityService
					.getHostAddressFromRequest(restRequest)
					.isLoopbackAddress()) {
				return xres.content();
						
			} else {
				throw new IOException("Only allowed from localhost (loopback)");
			}

		}

		if (xres.status().getStatus() < 200
				|| xres.status().getStatus() >= 300) {

			return xres.content();
		}

		if (!restRequest.path().contains("_search")
				&& !restRequest.path().contains("_msearch")
				&& !restRequest.path().contains("_mlt")
				&& !restRequest.path().contains("_suggest")) {

			return xres.content();
		}

		final List<String> dlsTokens = new PermDlsEvaluator(
				securityService.getXContentSecurityConfiguration(
						"dlspermissions", "dlspermissions")).evaluatePerm(
								SecurityUtil.getIndices(restRequest),
								SecurityUtil.getTypes(restRequest),
								securityService
								.getHostAddressFromRequest(restRequest),
								new TomcatUserRoleCallback(restRequest
										.getHttpServletRequest(),securityService.getSettings().get("security.ssl.userattribute")));

		log.debug("dls tokens: " + dlsTokens);

		// this.log.debug("orig json: " + xres.builder().string());

		final List<DlsPermission> perms = securityService
				.parseDlsPermissions(xres.content());

		// TODO check against the tokens

		final Tuple<XContentType, Map<String, Object>> mapTuple = XContentHelper
				.convertToMap(xres.content().toBytes(), true);

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
		
		if(!securityService.isStrictModeEnabled()){
			fields.add("facets"); 
			fields.add("suggest");
		}
		

		for (final DlsPermission p : perms) {

			if (p.isAnyTokenAllowedToRead(dlsTokens)) {

				fields.add("hits.hits._source." + p.getField());

			}

		}

		log.debug(fields.toString());

		final Map<String, Object> filteredSource = XContentMapValues.filter(
				mapTuple.v2(), fields.toArray(new String[0]), null);

		log.debug("filteredSource " + filteredSource);

		final XContentBuilder sourceToBeReturned = XContentFactory
				.contentBuilder(mapTuple.v1()).map(filteredSource);
		return sourceToBeReturned.bytes();

	}

}
