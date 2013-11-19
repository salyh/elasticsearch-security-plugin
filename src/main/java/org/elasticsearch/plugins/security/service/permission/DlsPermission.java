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
		return "DlsPermission [readTokens=" + this.readTokens
				+ ", updateTokens=" + this.updateTokens + ", deleteTokens="
				+ this.deleteTokens + ", field=" + this.field
				+ ", isDefault()=" + this.isDefault() + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime
				* result
				+ (this.deleteTokens == null ? 0 : this.deleteTokens.hashCode());
		result = prime * result
				+ (this.field == null ? 0 : this.field.hashCode());
		result = prime * result
				+ (this.readTokens == null ? 0 : this.readTokens.hashCode());
		result = prime
				* result
				+ (this.updateTokens == null ? 0 : this.updateTokens.hashCode());
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
		if (this.deleteTokens == null) {
			if (other.deleteTokens != null) {
				return false;
			}
		} else if (!this.deleteTokens.equals(other.deleteTokens)) {
			return false;
		}
		if (this.field == null) {
			if (other.field != null) {
				return false;
			}
		} else if (!this.field.equals(other.field)) {
			return false;
		}
		if (this.readTokens == null) {
			if (other.readTokens != null) {
				return false;
			}
		} else if (!this.readTokens.equals(other.readTokens)) {
			return false;
		}
		if (this.updateTokens == null) {
			if (other.updateTokens != null) {
				return false;
			}
		} else if (!this.updateTokens.equals(other.updateTokens)) {
			return false;
		}
		return true;
	}

	public DlsPermission() {

	}

	public boolean isDefault() {
		return this.field.equals("*");
	}

	public boolean isAllowNone() {
		return this.readTokens.isEmpty() && this.updateTokens.isEmpty()
				&& this.deleteTokens.isEmpty();
	}

	public boolean isTokenAllowedToRead(final String token) {
		return this.readTokens.contains(token) || this.readTokens.contains("*");
	}

	public boolean isTokenAllowedToUpdate(final String token) {
		return this.updateTokens.contains(token)
				|| this.updateTokens.contains("*");
	}

	public boolean isTokenAllowedToDelete(final String token) {
		return this.deleteTokens.contains(token)
				|| this.deleteTokens.contains("*");
	}

	public boolean isAnyTokenAllowedToDelete(final List<String> tokens) {
		return !Collections.disjoint(this.deleteTokens, tokens)
				|| this.deleteTokens.contains("*");
	}

	public boolean isAnyTokenAllowedToRead(final List<String> tokens) {
		return !Collections.disjoint(this.readTokens, tokens)
				|| this.readTokens.contains("*");
	}

	public boolean isAnyTokenAllowedToUpdate(final List<String> tokens) {
		return !Collections.disjoint(this.updateTokens, tokens)
				|| this.updateTokens.contains("*");
	}

	public String getField() {
		return this.field;
	}

	public void addReadToken(final String token) {
		this.addToken(token, this.readTokens);
	}

	public void addReadTokens(final String[] tokens) {
		for (final String token : tokens) {
			this.addToken(token, this.readTokens);
		}
	}

	public void addUpdateTokens(final String[] tokens) {
		for (final String token : tokens) {
			this.addToken(token, this.updateTokens);
		}
	}

	public void addDeleteTokens(final String[] tokens) {
		for (final String token : tokens) {
			this.addToken(token, this.deleteTokens);
		}
	}

	public void addUpdateToken(final String token) {
		this.addToken(token, this.updateTokens);
	}

	public void addDeleteToken(final String token) {
		this.addToken(token, this.deleteTokens);
	}

	private void addToken(final String token, final List<String> list) {
		if (token == null || token.trim().isEmpty() || token.contains(",")) {
			throw new IllegalArgumentException("'" + token
					+ "' is not a valid dls token");
		}
		list.add(token.trim());
	}

}
