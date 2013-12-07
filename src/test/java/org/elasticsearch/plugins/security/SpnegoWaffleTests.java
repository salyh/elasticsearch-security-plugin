package org.elasticsearch.plugins.security;

import java.util.Properties;

import org.junit.Before;

public class SpnegoWaffleTests extends SpnegoTests {

	@Override
	protected Properties getProperties() {
		final Properties props = new Properties();
		props.putAll(super.getProperties());
		props.setProperty("security.kerberos.mode", "waffle");
		props.setProperty("security.waffle.testmode", "true");
		return props;
	}


	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		headers.put("Authorization", "foo bar");
	}



}
