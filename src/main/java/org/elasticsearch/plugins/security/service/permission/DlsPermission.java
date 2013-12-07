package org.elasticsearch.plugins.security.service.permission;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class DlsPermission {

	public static DlsPermission ALL_PERMISSION = new DlsPermission();

	static {
		ALL_PERMISSION.addDeleteToken("*");
		ALL_PERMISSION.addReadToken("*");
		ALL_PERMISSION.addUpdateToken("*");
		ALL_PERMISSION.setField("*");
	}

	private final List<String> readTokens = new ArrayList<String>();
	private final List<String> updateTokens = new ArrayList<String>();
	private final List<String> deleteTokens = new ArrayList<String>();
	private String field;

	public void setField(final String field) {
		this.field = field.trim();
	}

	@Override
	public String toString() {
		return "DlsPermission [readTokens=" + readTokens
				+ ", updateTokens=" + updateTokens + ", deleteTokens="
				+ deleteTokens + ", field=" + field
				+ ", isDefault()=" + isDefault() + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime
				* result
				+ (deleteTokens == null ? 0 : deleteTokens.hashCode());
		result = prime * result
				+ (field == null ? 0 : field.hashCode());
		result = prime * result
				+ (readTokens == null ? 0 : readTokens.hashCode());
		result = prime
				* result
				+ (updateTokens == null ? 0 : updateTokens.hashCode());
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
		final DlsPermission other = (DlsPermission) obj;
		if (deleteTokens == null) {
			if (other.deleteTokens != null) {
				return false;
			}
		} else if (!deleteTokens.equals(other.deleteTokens)) {
			return false;
		}
		if (field == null) {
			if (other.field != null) {
				return false;
			}
		} else if (!field.equals(other.field)) {
			return false;
		}
		if (readTokens == null) {
			if (other.readTokens != null) {
				return false;
			}
		} else if (!readTokens.equals(other.readTokens)) {
			return false;
		}
		if (updateTokens == null) {
			if (other.updateTokens != null) {
				return false;
			}
		} else if (!updateTokens.equals(other.updateTokens)) {
			return false;
		}
		return true;
	}

	public DlsPermission() {

	}

	public boolean isDefault() {
		return field.equals("*");
	}

	public boolean isAllowNone() {
		return readTokens.isEmpty() && updateTokens.isEmpty()
				&& deleteTokens.isEmpty();
	}

	public boolean isTokenAllowedToRead(final String token) {
		return readTokens.contains(token) || readTokens.contains("*");
	}

	public boolean isTokenAllowedToUpdate(final String token) {
		return updateTokens.contains(token)
				|| updateTokens.contains("*");
	}

	public boolean isTokenAllowedToDelete(final String token) {
		return deleteTokens.contains(token)
				|| deleteTokens.contains("*");
	}

	public boolean isAnyTokenAllowedToDelete(final List<String> tokens) {
		return !Collections.disjoint(deleteTokens, tokens)
				|| deleteTokens.contains("*");
	}

	public boolean isAnyTokenAllowedToRead(final List<String> tokens) {
		return !Collections.disjoint(readTokens, tokens)
				|| readTokens.contains("*");
	}

	public boolean isAnyTokenAllowedToUpdate(final List<String> tokens) {
		return !Collections.disjoint(updateTokens, tokens)
				|| updateTokens.contains("*");
	}

	public String getField() {
		return field;
	}

	public void addReadToken(final String token) {
		addToken(token, readTokens);
	}

	public void addReadTokens(final String[] tokens) {
		for (final String token : tokens) {
			addToken(token, readTokens);
		}
	}

	public void addUpdateTokens(final String[] tokens) {
		for (final String token : tokens) {
			addToken(token, updateTokens);
		}
	}

	public void addDeleteTokens(final String[] tokens) {
		for (final String token : tokens) {
			addToken(token, deleteTokens);
		}
	}

	public void addUpdateToken(final String token) {
		addToken(token, updateTokens);
	}

	public void addDeleteToken(final String token) {
		addToken(token, deleteTokens);
	}

	private void addToken(final String token, final List<String> list) {
		if (token == null || token.trim().isEmpty() || token.contains(",")) {
			throw new IllegalArgumentException("'" + token
					+ "' is not a valid dls token");
		}
		list.add(token.trim());
	}

}
