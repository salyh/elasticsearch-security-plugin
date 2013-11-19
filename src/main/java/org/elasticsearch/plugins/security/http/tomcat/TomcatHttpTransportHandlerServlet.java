package org.elasticsearch.plugins.security.http.tomcat;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.http.HttpServerAdapter;

public class TomcatHttpTransportHandlerServlet extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	protected static final ESLogger log = Loggers
			.getLogger(TomcatHttpTransportHandlerServlet.class);
	private volatile TomcatHttpServerTransport transport;

	public TomcatHttpTransportHandlerServlet() {

	}

	@Override
	protected void service(final HttpServletRequest req,
			final HttpServletResponse resp) throws ServletException,
			IOException {

		final HttpServerAdapter adapter = this.getTransport()
				.httpServerAdapter();
		final TomcatHttpServerRestRequest restRequest = new TomcatHttpServerRestRequest(
				req);
		final TomcatHttpServerRestChannel restChannel = new TomcatHttpServerRestChannel(
				restRequest, resp, this.transport.getSecurityService());

		try {

			adapter.dispatchRequest(restRequest, restChannel);
			restChannel.await();

		} catch (final InterruptedException e) {
			throw new ServletException("failed to dispatch request", e);
		} catch (final Exception e) {
			throw new IOException("failed to dispatch request", e);
		}
		if (restChannel.sendFailure() != null) {
			throw new ServletException(restChannel.sendFailure());
		}

	}

	public TomcatHttpServerTransport getTransport() {
		return this.transport;
	}

	public void setTransport(final TomcatHttpServerTransport transport) {
		this.transport = transport;
		// this.logger = Loggers.getLogger(buildClassLoggerName(getClass()),
		// transport.settings());
	}

}
