elasticsearch-security-plugin
=============================
This plugins adds security functionality to elasticsearch in kind of separate modules.

[![Build Status](https://travis-ci.org/salyh/elasticsearch-security-plugin.png?branch=master)](https://travis-ci.org/salyh/elasticsearch-security-plugin)

As of now two security modules are implemented:
* Restrict actions against elasticsearch on IP-Address basis (actionpathfilter)
* Limit fields which will be returned on IP-Address basis (fieldresponsefilter)


<h3>Installation</h3>

Windows:
``plugin.bat --url http://goo.gl/1JwMKw --install elasticsearch-security-plugin-0.0.1.Beta1``

UNIX:
``plugin --url http://goo.gl/1JwMKw  --install elasticsearch-security-plugin-0.0.1.Beta1``



<h3>Configuration</h3>

<h4>Configuration (elasticsearch.yml)</h4>
Enable the security plugin
* ``http.type: org.elasticsearch.plugins.security.http.netty.NettyHttpServerTransportModule``

Optionally enable XFF 
* ``security.http.xforwardedfor.header: X-Forwarded-For`` Enable XFF
* ``security.http.xforwardedfor.trustedproxies: <List of proxy ip's>`` Example: 192.168.1.1, 31.122.45.1, 193.54.55.21
* ``security.http.xforwardedfor.enforce: true`` Enforce XFF header, default: false

<h4>Configuration (security rules)</h4>
The security rules for each module are stored in an index ``securityconfiguration``.

<b>Example: Configure 'Restrict actions against elasticsearch on IP-Address basis (actionpathfilter)' module</b>
<pre><code>$ curl -XPUT 'http://localhost:9200/securityconfiguration/actionpathfilter/actionpathfilter' -d '
{
			 "rules": [
			 	{
				 	"hosts" : [ "*" ],
				 	"indices" :[ "*" ],
				 	"permission" : "ALL"
			 	},
			 	
			 	{
				 	"hosts" : [ "google-public-dns-a.google.com" ],
				 	"indices" :[ "*"],
				 	"permission" : "NONE"
			 	},
			 	
			 	{
				 	"hosts" : [ "8.8.8.8" ],
				 	"indices" :[ "testindex1","testindex2" ],
				 	"permission" : "READWRITE"
			 	},
			 	
			 	{
				 	"hosts" : [ "81.*.8.*","2.44.12.14","*google.de","192.168.*.*" ],
				 	"indices" :[ "testindex1" ],
				 	"permission" : "READONLY"
			 	}
			 ]		 		 
}'</code></pre>

Permissions:
* ALL: No restrictions
* READWRITE: No admin actions but read write operations allowed
* READONLY: No admin and no write actions allowed (but read actions)
* NONE: No action allowd (also read actions will be denied)



<b>Example: Configure 'Limit fields which will be returned on IP-Address basis (fieldresponsefilter)' module</b>
<pre><code>$ curl -XPUT 'http://localhost:9200/securityconfiguration/fieldresponsefilter/fieldresponsefilter' -d '
{
			 "rules": [
			 	{
				 	"hosts" : [ "*" ],
				 	"indices" :[ "*" ],
				 	"fields" : "_id"
			 	},
			 	
			 	{
				 	"hosts" : [ "*mycompany.com" ],
				 	"indices" :[ "*"],
				 	"fields" : "*"
			 	},
			 	
			 	{
				 	"hosts" : [ "39.18.22.8" ],
				 	"indices" :[ "testindex1","testindex2" ],
				 	"fields" : "name,user,_id"
			 	},
			 	
			 	{
				 	"hosts" : [ "132.*.6.*","122.44.123.14","*google.de","192.168.1.*" ],
				 	"indices" :[ "testindex1","textindex3","myindex" ],
				 	"fields" : "timestamp,my.field.name,street,plz"
			 	}
			 ]		 		 
}'</code></pre>

Fields:
* List of fields (comma separated) which will be returned for a POST \_search/\_msearch query


In a more formal way the configuration looks like:

* Format is JSON
* One top level array named "rules"
* The single wildchar character (\*) match any host or any index
* In hostnames or ip's you can use the wildchar character (\*) for specifing subnets
* The rules elemens look like:

<pre><code>


			 	{
				 	"hosts" : [ &lt;* or list of hostnames/ip's for which this rule apply&gt; ],
				 	"indices" :[ &lt;* or list of indices for which this rule apply&gt; ],
				 	"&lt;qualification name\>" : &lt;qualification string&gt;
			 	}
			 	
</code></pre>
 
* There must be exactly one default rule:

<pre><code>


			 	{
				 	"hosts" : [ "*" ],
				 	"indices" :[ "*" ],
				 	"&lt;qualification name\>" : &lt;qualification string&gt;
			 	}
			 	
</code></pre>

* I more than one rule match then the last one (right down at the bottom of the security config) is used

