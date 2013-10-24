package org.elasticsearch.plugins.security;

public class MalformedConfigurationException extends Exception {

	private static final long serialVersionUID = 1L;

	public MalformedConfigurationException(final String message) {
		super(message);

	}

	public MalformedConfigurationException(final Throwable cause) {
		super(cause);

	}

	public MalformedConfigurationException(final String message,
			final Throwable cause) {
		super(message, cause);

	}

}
