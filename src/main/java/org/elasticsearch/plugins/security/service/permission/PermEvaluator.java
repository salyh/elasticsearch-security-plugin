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
					"securityconfiguration must not be null or empty");
		}

		this.xSecurityConfiguration = xSecurityConfiguration;

		// log.debug("Configuration: " + xSecurityConfiguration);
	}

	protected abstract T createFromString(String s);

	protected abstract String getPermissionFieldName();

	public T evaluatePerm(final List<String> indices, final List<String> types,
			final InetAddress hostAddress, final UserRoleCallback callback)
					throws MalformedConfigurationException {

		final List<Perm<T>> perms = new ArrayList<Perm<T>>();

		final List<WildcardIpOrHostname> matchList = new ArrayList<WildcardIpOrHostname>();

		try {

			this.parser = XContentFactory.xContent(this.xSecurityConfiguration)
					.createParser(this.xSecurityConfiguration);

			final String permissionFieldName = this.getPermissionFieldName();

			XContentParser.Token token;
			String currentFieldName = null;
			Perm<T> currentPerm = null;
			while ((token = this.parser.nextToken()) != null) {

				if (token == XContentParser.Token.START_OBJECT) {
					currentPerm = new Perm<T>();

				} else if (token == XContentParser.Token.END_OBJECT) {

					if (currentPerm != null && perms.contains(currentPerm)) {
						log.error("Duplicate permissions " + currentPerm);
						throw new MalformedConfigurationException(
								"Duplicate permissions found");
					}

					if (currentPerm != null && !currentPerm.isValid()) {
						log.error("Perm not valid " + currentPerm);
						throw new MalformedConfigurationException(
								"Invalid permission found");
					}

					if (currentPerm != null) {
						perms.add(currentPerm);
						currentPerm = null;
					}

				} else if (token == XContentParser.Token.FIELD_NAME) {
					currentFieldName = this.parser.currentName();

				} else if (token.isValue()) {

					if ("hosts".equals(currentFieldName)) {
						currentPerm.addInetAddress(this.parser.text());
					}
					if ("users".equals(currentFieldName)) {
						currentPerm.addUser(this.parser.text());
					}
					if ("roles".equals(currentFieldName)) {
						currentPerm.addRole(this.parser.text());
					} else if ("indices".equals(currentFieldName)) {
						currentPerm.addIndice(this.parser.text());
					} else if ("types".equals(currentFieldName)) {
						currentPerm.addType(this.parser.text());
					} else if (permissionFieldName.equals(currentFieldName)) {
						final String text = this.parser.text();
						currentPerm.setPermLevel(this
								.createFromString(text == null ? null : text
										.trim()));
					}

				}

			}

		} catch (final Exception e) {
			throw new MalformedConfigurationException(e);
		} finally {
			this.parser.close();
		}

		log.debug("Checking " + perms.size() + " perms");

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

		for (final Perm<T> p : perms) {

			for (final String ip : p.inetAddresses) {
				matchList.add(new WildcardIpOrHostname(ip));
			}
		}

		final WildcardIpOrHostname clientHostName = new WildcardIpOrHostname(
				hostAddress.getHostName());
		final WildcardIpOrHostname clientHostIp = new WildcardIpOrHostname(
				hostAddress.getHostAddress());

		permloop: for (final Perm<T> p : perms) {

			if (p.isDefault()) {
				continue;
			}

			String _role = null;
			String _host = null;

			log.debug("Check perm " + p);
//			log.debug("perm users " + p.users);

			// TODO difference between not here and []
			if (!p.users.isEmpty()
					&& !p.users.contains("*")
					&& (callback == null || callback.getRemoteuser() == null || !p.users
					.contains(callback.getRemoteuser()))) {
				log.debug("User " + callback.getRemoteuser()
						+ " does not match, so skip this permission");
				continue permloop;
			}

			log.debug("User "
					+ (callback == null ? "" : callback.getRemoteuser())
					+ " match");

//			log.debug("perm roles " + p.roles);
			
			if (!p.roles.contains("*") && !p.roles.isEmpty()) {
				if (callback == null) {
					log.debug("Role does not match, so skip this permission");
					continue permloop;
				}

				for (final String role : p.roles) {
					if (callback.isRemoteUserInRole(role)) {
						log.debug("Role " + role + " match");
						_role = role;
						break;
					}
				}

				if (_role == null) {
					log.debug("Role does not match, so skip this permission");
					continue permloop;
				}
			}

//			log.debug("perm hosts " + p.inetAddresses);
			
			if (!p.inetAddresses.contains("*") && !p.inetAddresses.isEmpty()) {
				for (final String pinetAddress : p.inetAddresses) {
					if (new WildcardIpOrHostname(pinetAddress)
					.equals(clientHostName)
					|| new WildcardIpOrHostname(pinetAddress)
					.equals(clientHostIp)) {

						log.debug("Host adress " + pinetAddress + " match");
						_host = pinetAddress;
						break;

					}

				}

				if (_host == null) {

					log.debug("Host adress ("
							+ clientHostIp.wildcardIpOrHostname
							+ "(ip) and "
							+ clientHostName.wildcardIpOrHostname
							+ " (hostname)does not match, so skip this permission");
					continue permloop;

				}

			}

		
			if (!p.types.isEmpty() && !p.types.contains("*")
					&& !p.types.containsAll(types)) {
				log.debug("Not all types match, so skip this permission ["
						+ p.types + " != " + types + "]");
				continue permloop;

			}

			log.debug("All types matches");

			log.debug("perm indices " + p.indices);
			
			if (!p.indices.isEmpty() && !p.indices.contains("*")
					&& !p.indices.containsAll(indices)) {

				log.debug("Not all indexes match, so skip this permission ["
						+ p.indices + " != " + indices + "]");
				continue permloop;

			}
			
			
			//@author - Ram Kotamaraja - START
			//added condition to check if indices provided are empty to validate the matching of index. This is required to allow requesting metadata queries like /_mapping, /_setting etc.
			else
			if(indices.isEmpty() && !p.indices.isEmpty() && !p.indices.contains("*") ){ 

				log.debug("Not all indexes match because no index specified, so skip this permission ["
						+ p.indices + " != " + indices + "]");
				continue permloop;
				
			}
			//@author - Ram Kotamaraja - END

			log.debug("All rules match, will apply " + p);
			return p.permLevel;

		}// end permloop

		log.debug("No rules matched, will apply default perm " + permLevel);
		return permLevel;

	}

	protected static class Perm<T> {

		private final List<String> inetAddresses = new ArrayList<String>();
		private final List<String> users = new ArrayList<String>();
		private final List<String> roles = new ArrayList<String>();
		private final List<String> indices = new ArrayList<String>();
		private final List<String> types = new ArrayList<String>();

		private T permLevel = null;

		public boolean isValid() {
			return this.permLevel != null;
		}

		// default is either all props empty and/or "*"
		public boolean isDefault() {

			if (this.inetAddresses.isEmpty() && this.users.isEmpty()
					&& this.roles.isEmpty() && this.indices.isEmpty()
					&& this.types.isEmpty()) {
				return true;
			}

			return (this.inetAddresses.isEmpty() ? true : this.inetAddresses
					.size() == 1 && "*".equals(this.inetAddresses.get(0)))
					&& (this.users.isEmpty() ? true : this.users.size() == 1
					&& "*".equals(this.users.get(0)))
					&& (this.roles.isEmpty() ? true : this.roles.size() == 1
					&& "*".equals(this.roles.get(0)))
					&& (this.types.isEmpty() ? true : this.types.size() == 1
					&& "*".equals(this.types.get(0)))
					&& (this.indices.isEmpty() ? true
							: this.indices.size() == 1
							&& "*".equals(this.indices.get(0)));
		}

		public void addInetAddress(final String inetAddress) {
			if (inetAddress == null || inetAddress.isEmpty()
					|| inetAddress.contains(",")) {
				throw new IllegalArgumentException("'" + inetAddress
						+ "' is not a valid inet address");
			}
			this.inetAddresses.add(inetAddress.trim());
		}

		public void addIndice(final String indice) {
			if (indice == null || indice.isEmpty() || indice.contains(",")) {
				throw new IllegalArgumentException("'" + indice
						+ "' is not a valid index name");
			}
			this.indices.add(indice.trim());
		}

		public void addUser(final String user) {
			if (user == null || user.isEmpty() || user.contains(",")) {
				throw new IllegalArgumentException("'" + user
						+ "' is not a valid user");
			}
			this.users.add(user.trim());
		}

		public void addRole(final String role) {
			if (role == null || role.isEmpty() || role.contains(",")) {
				throw new IllegalArgumentException("'" + role
						+ "' is not a valid role");
			}
			this.roles.add(role.trim());
		}

		public void addType(final String type) {
			if (type == null || type.isEmpty() || type.contains(",")) {
				throw new IllegalArgumentException("'" + type
						+ "' is not a valid type");
			}
			this.types.add(type.trim());
		}

		public void setPermLevel(final T permLevel) {

			if (permLevel == null) {
				throw new IllegalArgumentException("'" + permLevel
						+ "' is not a valid permLevel");
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
					+ (this.inetAddresses == null ? 0 : this.inetAddresses
							.hashCode());
			result = prime * result
					+ (this.roles == null ? 0 : this.roles.hashCode());
			result = prime * result
					+ (this.types == null ? 0 : this.types.hashCode());
			result = prime * result
					+ (this.users == null ? 0 : this.users.hashCode());
			return result;
		}

		@Override
		public boolean equals(final Object obj) {
			if (this == obj) {
				// log.debug("perm ==");
				return true;
			}
			if (obj == null) {
				// log.debug("perm other null");
				return false;
			}
			if (this.getClass() != obj.getClass()) {
				// log.debug("perm class mismatch");
				return false;
			}
			final Perm<?> other = (Perm<?>) obj;
			if (this.indices == null) {
				if (other.indices != null) {
					return false;
				}
			} else if (!equalLists(this.indices, other.indices)) {
				// log.debug("perm list not match: indices");
				return false;
			}
			if (this.inetAddresses == null) {
				if (other.inetAddresses != null) {
					return false;
				}
			} else if (!equalLists(this.inetAddresses, other.inetAddresses)) {
				// log.debug("perm list not match: inetaddr");
				return false;
			}
			if (this.roles == null) {
				if (other.roles != null) {
					return false;
				}
			} else if (!equalLists(this.roles, other.roles)) {
				// log.debug("perm list not match: roles");
				return false;
			}
			if (this.users == null) {
				if (other.users != null) {
					return false;
				}
			} else if (!equalLists(this.users, other.users)) {
				// log.debug("perm list not match: users");
				return false;
			}

			if (this.types == null) {
				if (other.types != null) {
					return false;
				}
			} else if (!equalLists(this.types, other.types)) {
				// log.debug("perm list not match: types");
				return false;
			}

			return true;
		}

		@Override
		public String toString() {
			return "Perm [inetAddresses=" + this.inetAddresses + ", users="
					+ this.users + ", roles=" + this.roles + ", indices="
					+ this.indices + ", types=" + this.types + ", permLevel="
					+ this.permLevel + ", isValid()=" + this.isValid()
					+ ", isDefault()=" + this.isDefault() + "]";
		}

	}

	private static boolean equalLists(final List<String> one,
			final List<String> two) {
		if (one == null && two == null) {
			return true;
		}

		if (one == null && two != null || one != null && two == null
				|| one.size() != two.size()) {
			return false;
		}

		return one.containsAll(two) && two.containsAll(one);
	}

	// TODO remove WildcardIpOrHostname class
	private static class WildcardIpOrHostname {
		// 192.*.168.*
		// server*:domain.*.com
		private final String wildcardIpOrHostname;

		// private static final ESLogger log = Loggers
		// .getLogger(PermEvaluator.class);

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

			/*
			 * if (log.isDebugEnabled()) { log.debug("REGEX " +
			 * this.getEscaped() + " on " + other.wildcardIpOrHostname +
			 * " matched? " + match); }
			 */

			return match;

		}

		private String getEscaped() {
			return this.wildcardIpOrHostname.replace(".", "\\.").replace("*",
					".*");

		}

	}

}
