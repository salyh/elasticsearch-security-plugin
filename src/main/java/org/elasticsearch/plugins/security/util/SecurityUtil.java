package org.elasticsearch.plugins.security.util;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.List;

import org.elasticsearch.common.Strings;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.rest.XContentRestResponse;
import org.elasticsearch.rest.XContentThrowableRestResponse;
import org.elasticsearch.rest.action.support.RestXContentBuilder;

public class SecurityUtil {

	private static final ESLogger log = Loggers.getLogger(SecurityUtil.class);

	private SecurityUtil() {

	}

	public static File getAbsoluteFilePathFromClassPath(
			final String fileNameFromClasspath) {

		File jaasConfigFile = null;
		final URL jaasConfigURL = SecurityUtil.class.getClassLoader()
				.getResource(fileNameFromClasspath);
		if (jaasConfigURL != null) {
			try {
				jaasConfigFile = new File(URLDecoder.decode(
						jaasConfigURL.getFile(), "UTF-8"));
			} catch (final UnsupportedEncodingException e) {
				return null;
			}

			if (jaasConfigFile.exists() && jaasConfigFile.canRead()) {
				return jaasConfigFile;
			} else {
				log.error(
						"Cannot read from {}, maybe the file does not exists? ",
						jaasConfigFile.getAbsolutePath());
			}

		} else {
			log.error("Failed to load " + fileNameFromClasspath);
		}

		return null;

	}

	public static boolean setSystemPropertyToAbsoluteFilePathFromClassPath(
			final String property, final String fileNameFromClasspath) {
		if (System.getProperty(property) == null) {
			File jaasConfigFile = null;
			final URL jaasConfigURL = SecurityUtil.class.getClassLoader()
					.getResource(fileNameFromClasspath);
			if (jaasConfigURL != null) {
				try {
					jaasConfigFile = new File(URLDecoder.decode(
							jaasConfigURL.getFile(), "UTF-8"));
				} catch (final UnsupportedEncodingException e) {
					return false;
				}

				if (jaasConfigFile.exists() && jaasConfigFile.canRead()) {
					System.setProperty(property,
							jaasConfigFile.getAbsolutePath());

					log.info("Load " + fileNameFromClasspath + " from {} ",
							jaasConfigFile.getAbsolutePath());
					return true;
				} else {
					log.error(
							"Cannot read from {}, maybe the file does not exists? ",
							jaasConfigFile.getAbsolutePath());
				}

			} else {
				log.error("Failed to load " + fileNameFromClasspath);
			}
		} else {
			log.warn("Property " + property + " already set to "
					+ System.getProperty(property));
		}

		return false;
	}

	public static boolean setSystemPropertyToAbsoluteFile(
			final String property, final String fileName) {
		if (System.getProperty(property) == null) {

			if (fileName == null) {
				log.error("Cannot set property " + property
						+ " because filename is null");

				return false;
			}

			final File jaasConfigFile = new File(fileName).getAbsoluteFile();

			if (jaasConfigFile.exists() && jaasConfigFile.canRead()) {
				System.setProperty(property, jaasConfigFile.getAbsolutePath());

				log.info("Load " + fileName + " from {} ",
						jaasConfigFile.getAbsolutePath());
				return true;
			} else {
				log.error(
						"Cannot read from {}, maybe the file does not exists? ",
						jaasConfigFile.getAbsolutePath());
			}

		} else {
			log.warn("Property " + property + " already set to "
					+ System.getProperty(property));
		}

		return false;
	}

	public static List<String> getIndices(final RestRequest request) {
		String[] indices = new String[0];
		final String path = request.path();
		// TODO all indices , length=0
		log.debug("Evaluate decoded path for indices'" + path + "'");

		if (!path.startsWith("/")) {

			return null;
		}

		if (path.length() > 1) {

			int endIndex;

			
			
			
			/*			if ((endIndex = path.indexOf('/', 1)) != -1) {
			indices = Strings.splitStringByCommaToArray(path.substring(1,
					endIndex));

		}
*/			
/**
*@author Ram Kotamaraja
*The above commented code handles code if there is a '/' at the end of the elastic search indices. Code is modified to handle indices where there is no '/' after it.
*Code below also handles the root level queries like '/_mapping', '/_settings' etc.			
*/

		//Code modification START - Ram Kotamaraja
		if ((path.indexOf('/', 1)) != -1) {
			endIndex = path.indexOf('/', 1);
		}else{
			endIndex = path.length();
		}

		//check if the index start with /_. If it is not staring, then parse path, if not do nothing to return empty object			
		if (!path.trim().startsWith("/_")) {
			indices = Strings.splitStringByCommaToArray(path.substring(1,endIndex));
		}
		
		//Code modification END - Ram Kotamaraja
			
			
			
			
		}

		log.debug("Indices: " + Arrays.toString(indices));
		return Arrays.asList(indices);

	}

	public static String getId(final RestRequest request) {

		String id = null;
		final String path = request.path();

		log.debug("Evaluate decoded path for id '" + path + "'");

		if (!path.startsWith("/")) {

			return null;
		}

		if (path.length() > 1) {

			int endIndex;

			if ((endIndex = path.lastIndexOf('/')) != -1) {
				id = path.substring(endIndex + 1);

				if (id.contains("?")) {
					id = path.substring(id.indexOf("?") + 1);

				}

				// if(id.contains("/")) return null;

			}
		}

		log.debug("Id: " + id);
		return id;

	}

	public static List<String> getTypes(final RestRequest request) {
		String[] types = new String[0];
		final String path = request.path();

		// TODO all types, length=0 or _all ??
		// TODO aliases indices get expanded before or after rest layer?
		log.debug("Evaluate decoded path for types '" + path + "'");

		if (!path.startsWith("/")) {

			return null;
		}

		if (path.length() > 1) {

			int endIndex;

			if ((endIndex = path.indexOf('/', 1)) != -1) {

				int endType;

				if ((endType = path.indexOf('/', endIndex + 1)) != -1) {

					types = Strings.splitStringByCommaToArray(path.substring(
							endIndex + 1, endType));
				}

			}
		}

		log.debug("Types: " + Arrays.toString(types));
		return Arrays.asList(types);

	}

	public static void send(final RestRequest request,
			final RestChannel channel, final RestStatus status, final String arg) {
		try {
			final XContentBuilder builder = RestXContentBuilder
					.restContentBuilder(request);
			builder.startObject();
			builder.field("status", status.getStatus());

			if (arg != null && !arg.isEmpty()) {
				builder.field("message", arg);
			}

			builder.endObject();
			channel.sendResponse(new XContentRestResponse(request, status,
					builder));
		} catch (final Exception e) {
			log.error("Failed to send a response.", e);
			try {
				channel.sendResponse(new XContentThrowableRestResponse(request,
						e));
			} catch (final IOException e1) {
				log.error("Failed to send a failure response.", e1);
			}
		}
	}
	

	public static String[] BUILT_IN_ADMIN_COMMANDS = new String[] { "_cluster",
		"_settings", "_close", "_open", "_template", "_status", "_stats",
		"_segments", "_cache", "_gateway", "_optimize", "_flush",
		"_warmer", "_refresh", "_shutdown"};

	public static String[] BUILT_IN_WRITE_COMMANDS_STRICT = new String[] { "_create",
		"_update", "_bulk", "_percolator","_mapping", "_aliases", "_analyze"};

	public static String[] BUILT_IN_READ_COMMANDS_STRICT = new String[] { "_search",
	"_msearch","_mlt", "_explain", "_validate","_count","_suggest", "_percolate",  "_nodes"};


	public static String[] BUILT_IN_WRITE_COMMANDS_LAX = new String[] { "_create",
		"_update", "_bulk"};

	public static String[] BUILT_IN_READ_COMMANDS_LAX = new String[] { "_search",
	"_msearch","_mlt", "_explain", "_validate","_count","_suggest", "_percolate",  "_nodes", "_percolator","_mapping", "_aliases", "_analyze"};
	
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

	public static boolean stringContainsItemFromListAsTypeOrIndex(
			final String inputString, final String[] items) {
		for (int i = 0; i < items.length; i++) {
			if (inputString.contains("/" + items[i] + "/")) {
				return true;
			}
		}
		return false;
	}

	public static boolean isWriteRequest(final RestRequest request, boolean strictModeEnabled) {
		if (request.method() == Method.DELETE || request.method() == Method.PUT) {
			return true;
		}

		if (request.method() == Method.POST) {
			if (!stringContainsItemFromListAsCommand(request.path(),
					strictModeEnabled?SecurityUtil.BUILT_IN_READ_COMMANDS_STRICT : SecurityUtil.BUILT_IN_READ_COMMANDS_LAX)) {
				return true;
			}
		}

		return stringContainsItemFromListAsCommand(request.path(),
				strictModeEnabled?SecurityUtil.BUILT_IN_WRITE_COMMANDS_STRICT : SecurityUtil.BUILT_IN_WRITE_COMMANDS_LAX);
	}

	public static boolean isAdminRequest(final RestRequest request) {
		return stringContainsItemFromListAsCommand(request.path(),
				BUILT_IN_ADMIN_COMMANDS);
	}

	public static boolean isReadRequest(final RestRequest request, boolean strictModeEnabled) {
		return !isWriteRequest(request, strictModeEnabled) && !isAdminRequest(request);
	}
}
