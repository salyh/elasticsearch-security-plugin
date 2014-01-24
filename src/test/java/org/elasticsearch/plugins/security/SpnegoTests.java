package org.elasticsearch.plugins.security;

import io.searchbox.client.JestResult;

import java.util.Properties;

import org.junit.Assert;
import org.junit.Test;

public abstract class SpnegoTests extends AbstractUnitTest {

	@Override
	protected Properties getProperties() {

		final Properties props = new Properties();
		props.putAll(super.getProperties());
		props.setProperty("security.http.xforwardedfor.header",
				"X-Forwarded-For");
		props.setProperty("security.http.xforwardedfor.trustedproxies",
				"123.123.123.123, 111.222.111.222");
		return props;
	}



	// ---

	@Test
	public void common_normalTest() throws Exception {

		executeIndex("ur_test_normal.json","securityconfiguration","actionpathfilter","actionpathfilter",true);
		executeIndex("dummy_content.json","twitter","tweet","1",true);

	}

	@Test
	public void common_dupTest() throws Exception {


		executeIndex("ur_test_duplicate.json","securityconfiguration","actionpathfilter","actionpathfilter",true);
		executeIndex("dummy_content.json","twitter","tweet","1",false);

	}

	// --

	@Test
	public void singleHeaderTest() throws Exception {

		executeIndex("test_normal.json","securityconfiguration","actionpathfilter","actionpathfilter",true);
		executeIndex("dls_default_test_allowall.json","securityconfiguration","dlspermissions","default",true);
		executeIndex("fls_test_normal.json","securityconfiguration","dlspermissions","dlspermissions",true);

		headers.put("X-Forwarded-For", "3.1.55.2");
		executeSearch("non_field_query.json",true);

	}

	@Test
	public void badProxiesTest() throws Exception {

		executeIndex("dls_default_test_allowall.json",
				"securityconfiguration", "dlspermissions", "default", true);

		executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);

		executeIndex("test_normal.json", "securityconfiguration", "actionpathfilter", "actionpathfilter",true );

		headers.put("X-Forwarded-For",
				"3.1.55.2, 123.12.123.123, 111.222.111.222");
		executeSearch("non_field_query.json", false);


	}

	@Test
	public void goodProxiesTest() throws Exception {

		executeIndex("dls_default_test_allowall.json",
				"securityconfiguration", "dlspermissions", "default", true);

		executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);

		executeIndex("test_normal.json", "securityconfiguration", "actionpathfilter", "actionpathfilter",true );


		headers.put("X-Forwarded-For",
				"3.1.55.2, 123.123.123.123, 111.222.111.222");
		executeSearch("non_field_query.json", true);



	}

	@Test
	public void goodProxiesTestSingle() throws Exception {

		executeIndex("dls_default_test_allowall.json",
				"securityconfiguration", "dlspermissions", "default", true);

		executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);

		executeIndex("test_normal.json", "securityconfiguration", "actionpathfilter", "actionpathfilter",true );


		headers.put("X-Forwarded-For",
				"3.1.55.2, 123.123.123.123");
		executeSearch("non_field_query.json", true);


	}


	// --
	@Test
	public void normalTest2() throws Exception {

		executeIndex("dls_default_test_denyall.json",
				"securityconfiguration", "dlspermissions", "default", true);
		executeIndex("ur_test_normal.json", "securityconfiguration",
				"actionpathfilter", "actionpathfilter", true);
		executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);
		executeIndex("fls_dummy_content.json", "twitter", "tweet", "1",
				true);
		executeIndex("dls_dummy_content_without_dls.json", "twitter",
				"tweet", "2", true);
		executeSearch("fls_field_query.json", true);

	}

	@Test
	public void normalTest22() throws Exception {


		executeIndex("ur_test_normal.json", "securityconfiguration", "actionpathfilter", "actionpathfilter",true );

		executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);


		executeIndex("dls_dummy_content_without_dls.json", "twitter",
				"tweet", "1", true);

		executeSearch("fls_field_query.json", true);

	}

	// --
	// dls

	@Test
	public void normalTest() throws Exception {

		executeIndex("ur_test_normal.json", "securityconfiguration", "actionpathfilter", "actionpathfilter",true );

		executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);

		executeIndex("fls_dummy_content.json", "twitter",
				"tweet", "1", true);

		executeIndex("fls_dummy_content_updt.json", "twitter",
				"tweet", "1", true);


		executeSearch("fls_field_query.json", true);

	}
	
	@Test
	public void facetTest() throws Exception {

		executeIndex("ur_test_all.json", "securityconfiguration", "actionpathfilter", "actionpathfilter",true );

		executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);

		executeIndex("fls_dummy_content.json", "twitter",
				"tweet", "1", true);

		JestResult res = executeSearch("test_facet_search.json", true);
 
		Assert.assertTrue(res.getJsonString().contains("facets"));
		Assert.assertTrue(res.getJsonString().contains("term"));
		

	}
	
	/*@Test
	public void facetTestStrict() throws Exception {

		this.esSetup..put("security.strict", "true");
		
		executeIndex("ur_test_all.json", "securityconfiguration", "actionpathfilter", "actionpathfilter",true );

		executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);

		executeIndex("fls_dummy_content.json", "twitter",
				"tweet", "1", true);

		JestResult res = executeSearch("test_facet_search.json", true);
 
		Assert.assertTrue(!res.getJsonString().contains("facets"));
		Assert.assertTrue(!res.getJsonString().contains("term"));
		

	}*/

	@Test
	public void normalTest23() throws Exception {

		executeIndex("ur_test_normal.json", "securityconfiguration", "actionpathfilter", "actionpathfilter",true );


		executeIndex("fls_test_normal.json", "securityconfiguration",
				"dlspermissions", "dlspermissions", true);

		executeIndex("fls_dummy_content.json", "twitter",
				"tweet", "1", true);

		executeSearch("fls_field_query.json", true);

	}

	// --

	@Test
	public void denyAllTest() throws Exception {

		executeIndex("test_denyall.json", "securityconfiguration", "actionpathfilter", "actionpathfilter",true );


		executeIndex("dummy_content.json", "twitter",
				"tweet", "1", false);



	}

	@Test
	public void allowTest() throws Exception {


		executeIndex("test_normal.json", "securityconfiguration", "actionpathfilter", "actionpathfilter",true );



		executeIndex("dummy_content.json", "twitter",
				"tweet", "1", true);


	}






}
