package org.elasticsearch.plugins.security;

import io.searchbox.client.JestClient;
import io.searchbox.client.JestClientFactory;
import io.searchbox.client.config.HttpClientConfig;
import io.searchbox.client.http.JestHttpClient;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.Header;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.plugins.security.util.SecurityUtil;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class BasicAuthTests extends AbstractUnitTest {

	@Override
	protected Properties getProperties() {

		final Properties props = new Properties();
		props.putAll(super.getProperties());
		props.setProperty("security.kerberos.mode",
				"none");
        props.setProperty("security.basic.mode",
                "true");
        props.setProperty("security.basic.users.file",
                SecurityUtil.getAbsoluteFilePathFromClassPath("users.xml").getAbsolutePath());
		return props;
	}

    public BasicAuthTests() {
        super();
    }

    @Override
    protected String [] getUserPass()
    {
        return new String[]{"hnelson", "tomcat"};
    }

    @Override
    protected JestHttpClient getJestClient(String serverUri, final String username,
                                         final String password) throws Exception {// http://hc.apache.org/httpcomponents-client-ga/tutorial/html/authentication.html
        final HttpClientConfig clientConfig1 = new HttpClientConfig.Builder(serverUri)
                .multiThreaded(true).build();

        // Construct a new Jest client according to configuration via factory
        final JestClientFactory factory1 = new JestClientFactory();

        factory1.setHttpClientConfig(clientConfig1);

        final JestHttpClient c = (JestHttpClient) factory1.getObject();

        final HttpClientBuilder hcb = HttpClients.custom();
        String authHeader = "Basic " + new String(Base64.encodeBase64(String.format("%s:%s", username, password).getBytes()));
        final List<Header> dh = new ArrayList<Header>();
        dh.add(new BasicHeader("Authorization", authHeader));
        hcb.setDefaultHeaders(dh);
        c.setHttpClient(hcb.build());
        return c;
    }

	@Test
	public void common_normalTest() throws Exception {

		executeIndex("ur_test_basic.json","securityconfiguration","actionpathfilter","actionpathfilter",true);
        executeIndex("dummy_content.json","twitter","tweet","1",true);
        executeIndex("dummy_content.json","twitter_test","tweet","1",false);

	}

}
