package org.elasticsearch.plugins.security.service.permission;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.plugins.security.MalformedConfigurationException;

public abstract class PermEvaluator<T> {

	protected static final ESLogger log = Loggers
			.getLogger(PermEvaluator.class);
	protected final String xSecurityConfiguration;
	protected XContentParser parser = null;

	protected PermEvaluator(final String xSecurityConfiguration) {
		super();

		if (xSecurityConfiguration == null || xSecurityConfiguration.isEmpty()) {
			throw new IllegalArgumentException(
					"Securityconfiguration must not be null or empty");
		}

		this.xSecurityConfiguration = xSecurityConfiguration;

		log.debug("Configuration: " + xSecurityConfiguration);
	}

	protected abstract T createFromString(String s);

	public T evaluatePerm(final List<String> indices,
			final InetAddress hostAddress)
			throws MalformedConfigurationException {

		

		final List<Perm<T>> perms = new ArrayList<Perm<T>>();
		final List<WildcardIpOrHostname> matchList = new ArrayList<WildcardIpOrHostname>();

		try {
			
			this.parser = XContentFactory.xContent(this.xSecurityConfiguration)
					.createParser(this.xSecurityConfiguration);
			
			XContentParser.Token token;
			String currentFieldName = null;
			Perm<T> currentPerm= null;
			while ((token = this.parser.nextToken()) != null) {

				if (token == XContentParser.Token.START_OBJECT) {
					currentPerm= new Perm<T>();
				} else if (token == XContentParser.Token.END_OBJECT) {
					perms.add(currentPerm);
				} else if (token == XContentParser.Token.FIELD_NAME) {
					currentFieldName = this.parser.currentName();
			
				} else if (token.isValue()) {				

					if ("hosts".equals(currentFieldName)) {
						currentPerm.setInetAddress(this.parser.text());
					} else if ("indices".equals(currentFieldName)) {						
						currentPerm.addIndice(this.parser.text());
					} else if ("permission".equals(currentFieldName)) {
						currentPerm.setPermLevel(this
								.createFromString(this.parser.text()));
					}

				}

			}
			
		}catch(Exception e)
		{
			throw new MalformedConfigurationException(e);
		}
		finally {
			this.parser.close();
		}

		for (final Perm<T>p : perms) {
			matchList.add(new WildcardIpOrHostname(p.inetAddress));
		}

		T permLevel = null;

		for (final Perm<T> p : perms) {

			if (p.isDefault()) {
				permLevel = p.permLevel;
				if (log.isDebugEnabled()) {
					log.debug("Default set to " + permLevel);
				}
				break;
			}
		}

		if (permLevel == null) {
			throw new MalformedConfigurationException(
					"No default configuration found");
		}

		final WildcardIpOrHostname clientHostName = new WildcardIpOrHostname(
				hostAddress.getHostName());
		final WildcardIpOrHostname clientHostIp = new WildcardIpOrHostname(
				hostAddress.getHostAddress());

		if (log.isDebugEnabled()) {
			log.debug("Checking  " + clientHostIp.wildcardIpOrHostname
					+ "(ip) and " + clientHostName.wildcardIpOrHostname
					+ " (hostname)");
		}

		for (final Perm<T> p : perms) {
			if (new WildcardIpOrHostname(p.inetAddress).equals(clientHostName)
					|| new WildcardIpOrHostname(p.inetAddress)
							.equals(clientHostIp)) {
				log.debug(p.inetAddress + " match");

				if (p.indices.get(0).equals("*")
						|| p.indices.containsAll(indices)) {
					log.debug("All indexes match, will apply this permission");

					
					if (permLevel != p.permLevel) {
						log.debug("Adjust permlevel from " + permLevel + " to "
								+ p.permLevel);
						permLevel = p.permLevel;
						
					}
				} else {
					log.debug("Not all indexes match, so skip this permission");
					log.debug(p.indices +" != "+indices);
				}

			} else {
				log.debug(p.inetAddress + " does not match");
			}
		}

		log.debug("Permlevel for " + hostAddress + " is " + permLevel);

		return permLevel;
	}

	protected static class Perm<T> {
		
		private String inetAddress = null;
		private final List<String> indices = new ArrayList<String>();
		private T permLevel = null;

		public boolean isDefault() {
			return "*".equals(this.inetAddress) && this.indices.size() == 1
					&& "*".equals(this.indices.get(0));
		}

		public void setInetAddress(final String inetAddress) {
			
			if(inetAddress == null || inetAddress.isEmpty() || inetAddress.contains(","))
			{
				throw new IllegalArgumentException("'"+inetAddress+"' is not a valid host name");
			}
			
			this.inetAddress = inetAddress;
		}

		public void addIndice(final String indice) {
			if(indice == null || indice.isEmpty() || indice.contains(","))
			{
				throw new IllegalArgumentException("'"+indice+"' is not a valid index name");
			}
			this.indices.add(indice);
		}

		public void setPermLevel(final T permLevel) {
			
			if(permLevel == null)
			{
				throw new IllegalArgumentException("'"+permLevel+"' is not a valid permLevel");
			}
			
			this.permLevel = permLevel;
		}
	

		public Perm() {

		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result
					+ (this.indices == null ? 0 : this.indices.hashCode());
			result = prime
					* result
					+ (this.inetAddress == null ? 0 : this.inetAddress
							.hashCode());
			return result;
		}

		@Override
		public boolean equals(final Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (this.getClass() != obj.getClass()) {
				return false;
			}
			@SuppressWarnings("unchecked")
			final Perm<T> other = (Perm<T>) obj;
			if (this.indices == null) {
				if (other.indices != null) {
					return false;
				}
			} else if (!this.indices.equals(other.indices)) {
				return false;
			}
			if (this.inetAddress == null) {
				if (other.inetAddress != null) {
					return false;
				}
			} else if (!this.inetAddress.equals(other.inetAddress)) {
				return false;
			}
			return true;
		}

	}

	private static class WildcardIpOrHostname {
		// 192.*.168.*
		// server*:domain.*.com
		private final String wildcardIpOrHostname;
		private static final ESLogger log = Loggers
				.getLogger(PermEvaluator.class);

		public WildcardIpOrHostname(final String wildcardIpOrHostname) {
			super();
			this.wildcardIpOrHostname = wildcardIpOrHostname;
		}

		@Override
		public int hashCode() {
			throw new RuntimeException("not implemented");
		}

		@Override
		public boolean equals(final Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (this.getClass() != obj.getClass()) {
				return false;
			}
			final WildcardIpOrHostname other = (WildcardIpOrHostname) obj;

			

			final Pattern p = Pattern.compile(this.getEscaped());
			final Matcher m = p.matcher(other.wildcardIpOrHostname);
			final boolean match = m.matches();
			
			if (log.isDebugEnabled()) {
				log.debug("REGEX " + this.getEscaped() + " on "
						+ other.wildcardIpOrHostname +" matched? "+match);
			}


			return match;

			
		}

		private String getEscaped() {
			return this.wildcardIpOrHostname.replace(".", "\\.").replace("*",
					".*");

		}

	}

}
