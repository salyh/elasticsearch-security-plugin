package org.elasticsearch.plugins.security.filter;

import java.util.ArrayList;
import java.util.List;

import org.elasticsearch.plugins.security.service.permission.PermEvaluator;

public class PermDlsEvaluator extends PermEvaluator<List<String>> {

	public PermDlsEvaluator(final String xSecurityConfiguration) {
		super(xSecurityConfiguration);

	}

	@Override
	protected List<String> createFromString(final String s) {

		final List<String> fields = new ArrayList<String>();

		if (s == null) {
			return fields;
		}

		final String[] split = s.split(",");

		for (int i = 0; i < split.length; i++) {
			fields.add(split[i]);
		}

		return fields;

	}

	@Override
	protected String getPermissionFieldName() {
		return "dlstoken";
	}

}
