package org.elasticsearch.plugins.security;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class SpnegoWaffleTests extends SpnegoTests {

	@Override
	protected Properties getProperties() {
		final Properties props = new Properties();
		props.putAll(super.getProperties());

		props.setProperty("security.kerberosimpl", "waffle");
		props.setProperty("security.waffle.testmode", "true");

		System.out.println("waffle props " + props);

		return props;
	}

	@Override
	protected Map<String, Object> getHeaderMap() {
		final Map<String, Object> map = new HashMap<String, Object>();
		map.putAll(super.getHeaderMap());
		map.put("Authorization", "foo bar");
		return map;
	}

}
