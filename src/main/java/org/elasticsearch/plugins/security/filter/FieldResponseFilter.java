package org.elasticsearch.plugins.security.filter;

import java.util.ArrayList;
import java.util.List;

import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentParser.Token;
import org.elasticsearch.plugins.security.MalformedConfigurationException;
import org.elasticsearch.plugins.security.service.SecurityService;
import org.elasticsearch.plugins.security.util.EditableRestRequest;
import org.elasticsearch.plugins.security.util.SecurityUtil;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestStatus;

public class FieldResponseFilter extends SecureRestFilter {

	public FieldResponseFilter(final SecurityService securityService) {
		super(securityService);

	}

	protected XContentBuilder addFields(final XContentParser parser,
			List<String> fields) throws Exception {

		if (fields == null || fields.isEmpty()) {
			fields = new ArrayList<String>();

			fields.add("_id");
		}
		String currentName = null;
		XContentParser.Token currentToken = parser.nextToken();

		while (currentToken != null
				&& (currentName = parser.currentName()) != "query") {
			currentToken = parser.nextToken();

		}

		if (currentToken != Token.FIELD_NAME) {
			throw new Exception("Found " + currentToken + " but expected "
					+ Token.FIELD_NAME);
		}
		if (!currentName.equals("query")) {
			throw new Exception("Node name is '" + parser.currentName()
					+ "' but expected was 'query'");
		}

		final XContentBuilder builder = XContentFactory.contentBuilder(parser
				.contentType());
		builder.startObject();
		builder.startArray("fields");

		for (final String f : fields) {
			builder.value(f);

		}

		builder.endArray();
		// start with field "query"
		builder.copyCurrentStructure(parser);
		builder.endObject();
		builder.close();
		return builder;
	}

	@Override
	public void processSecure(final RestRequest request,
			final RestChannel channel, final RestFilterChain filterChain) {

		if (!request.path().contains("_search")
				&& !request.path().contains("_msearch")) {
			this.log.debug("Not a search request");
			filterChain.continueProcessing(request, channel);
			return;
		}

		if (request.method() != Method.POST) {
			SecurityUtil
					.send(request,
							channel,
							RestStatus.FORBIDDEN,

							"Only _search requests with method POST are allowed. Change your search query from GET to POST");
			return;
		}

		if (!request.hasContent()) {
			SecurityUtil.send(request, channel, RestStatus.BAD_REQUEST,
					"POST content missing");
			return;
		}

		this.log.debug("unmodified content " + request.content().toUtf8());
		XContentParser parser = null;

		try {

			final List<String> fields = new PermFieldsEvaluator(
					this.securityService.getXContentConfiguration(
							this.getType(), this.getId())).evaluatePerm(
					this.getIndices(request),
					this.getClientHostAddress(request));

			if (fields == null || fields.size() == 0) {
				throw new MalformedConfigurationException(
						"fields are null or empty");
			}

			if (fields.size() == 1 && "*".equals(fields.get(0))) {
				this.log.debug("Field wildcard found, will not modify request");
				filterChain.continueProcessing(request, channel);
			} else {
				parser = XContentFactory.xContent(
						XContentFactory.xContentType(request.content()))
						.createParser(request.content());

				final EditableRestRequest newRequest = new EditableRestRequest(
						request);
				newRequest.setContent(this.addFields(parser, fields).bytes());
				this.log.debug("returned modified content "
						+ newRequest.content().toUtf8());
				filterChain.continueProcessing(newRequest, channel);
			}
		} catch (final Exception e) {
			this.log.error("Could not parse the content", e);
			SecurityUtil.send(request, channel, RestStatus.BAD_REQUEST,
					"Could not parse the content");

			return;
		} finally {
			if (parser != null) {
				// parser.close();
			}
		}

	}

	@Override
	protected String getType() {

		return "fieldresponsefilter";
	}

	@Override
	protected String getId() {

		return "fieldresponsefilter";
	}

}

/*
 * 
 * 
 * { "limitresponsefields": [ { "hosts" : [ "*" ], "indices" :[ "*" ], "fields"
 * : "_id" }, { "hosts" : [ "1.2.3.4" ], "indices" :[ "*" ], "fields" :
 * "name,street,mail" }, { "hosts" : [ "127.0.0.1" ], "indices" :[
 * "testindex1","testindex2" ], "fields" : "*" }, { "hosts" : [ "8.8.8.8" ],
 * "indices" :[ "testindex1","testindex2"], "fields" : "name" } ] }
 */