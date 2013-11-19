package org.elasticsearch.plugins.security.http.tomcat;

import java.util.LinkedList;
import java.util.List;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;

import net.sf.michaelo.tomcat.utils.LdapUtils;



import org.apache.commons.lang.StringUtils;
import org.ietf.jgss.GSSName;

public class UniversalLdapRealm extends FixedActiveDirectoryRealm {

	private String usersSearchPattern = "(&(objectClass=krb5principal) (krb5PrincipalName={0}))"; // 0=hnelson@example.com
																									// 1=hnelson
	private String groupsSearchPattern = "(&(objectClass=groupofnames)(member={0}))"; // 0=dn
																						// of
																						// user,
																						// 1=hnelson@example.com
																						// 2=hnelson
	private String groupsSearchBase = "";
	private String userSearchBase = "";
	private String roleNameAttribute = "cn";

	public String getUsersSearchPattern() {
		return this.usersSearchPattern;
	}

	public void setUsersSearchPattern(final String usersSearchPattern) {
		this.usersSearchPattern = usersSearchPattern;
	}

	public String getGroupsSearchPattern() {
		return this.groupsSearchPattern;
	}

	public void setGroupsSearchPattern(final String groupsSearchPattern) {
		this.groupsSearchPattern = groupsSearchPattern;
	}

	public String getGroupsSearchBase() {
		return this.groupsSearchBase;
	}

	public void setGroupsSearchBase(final String groupsSearchBase) {
		this.groupsSearchBase = groupsSearchBase;
	}

	public String getUserSearchBase() {
		return this.userSearchBase;
	}

	public void setUserSearchBase(final String userSearchBase) {
		this.userSearchBase = userSearchBase;
	}

	public String getRoleNameAttribute() {
		return this.roleNameAttribute;
	}

	public void setRoleNameAttribute(final String roleNameAttribute) {
		this.roleNameAttribute = roleNameAttribute;
	}

	public UniversalLdapRealm() {

	}

	@Override
	protected User getUser(final DirContext context, final GSSName gssName)
			throws NamingException {

		this.logger.debug("LdapRealm getUser() " + gssName.toString());

		final SearchControls searchCtls = new SearchControls();
		searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		final String searchAttributeValue = gssName.toString();
		String searchAttributeValueStripped = gssName.toString();

		if (searchAttributeValueStripped.contains("@")) {
			searchAttributeValueStripped = searchAttributeValueStripped
					.substring(0, searchAttributeValueStripped.indexOf("@"));
			this.logger.debug(String.format("Stripped User '%s'",
					searchAttributeValueStripped));
		}

		final NamingEnumeration<SearchResult> results = context.search(
				this.userSearchBase, this.usersSearchPattern, new Object[] {
						searchAttributeValue, searchAttributeValueStripped },
				searchCtls);

		if (results == null || !results.hasMore()) {
			LdapUtils.close(results);
			this.logger.info(String.format("User '%s' not found", gssName));
			return null;
		}

		final SearchResult result = results.next();

		if (results.hasMore()) {
			this.logger.warn(String.format("User '%s' has multiple entries",
					gssName));
			return null;
		}

		final LdapName dn = this.getDistinguishedName(context,
				this.userSearchBase, result);

		if (this.logger.isDebugEnabled()) {
			this.logger.debug(String.format(
					"Entry found for user '%s' with DN '%s'", gssName, dn));

		}

		final SearchControls groupsSearchCtls = new SearchControls();
		groupsSearchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

		final NamingEnumeration<SearchResult> gropupsResults = context.search(
				this.groupsSearchBase, this.groupsSearchPattern, new Object[] {
						dn.toString(), searchAttributeValue,
						searchAttributeValueStripped }, groupsSearchCtls);

		final List<String> roles = new LinkedList<String>();

		while (gropupsResults.hasMoreElements()) {

			final SearchResult groupsSR = gropupsResults.nextElement();
			roles.add(this.getDistinguishedName(context, this.groupsSearchBase,
					groupsSR).toString()); // cn parsed

		}

		LdapUtils.close(gropupsResults);

		return new User(gssName, null, dn, roles);
	}

	@Override
	protected List<String> getRoles(final User user) throws NamingException {

		final List<String> roles = new LinkedList<String>();

		if (this.logger.isTraceEnabled()) {
			this.logger.trace(String.format(
					"Retrieving roles for user '%s' with DN '%s'",
					user.getGssName(), user.getDn()));
		}

		for (String role : user.getRoles()) {
			role = StringUtils.substringBetween(role.toLowerCase(),
					(this.roleNameAttribute + "=").toLowerCase(), ",");

			if (role != null) {
				roles.add(role);
			}
		}

		if (this.logger.isDebugEnabled()) {
			this.logger.debug(String.format("Found %s roles for user '%s'",
					roles.size(), user.getGssName()));
		}
		if (this.logger.isTraceEnabled()) {
			this.logger.debug(String.format(
					"Found following roles %s for user '%s'", roles,
					user.getGssName()));
		}

		return roles;
	}

}
