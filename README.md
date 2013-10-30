elasticsearch-security-plugin
=============================
This plugins adds security functionality to elasticsearch in kind of separate modules.

As of now two security modules are implemented:
* Restrict actions against elasticsearch on IP-Address basis (actionpathfilter)
* Limit fields which will be returned on IP-Address basis (fieldresponsefilter)


<h3>Installation</h3>

plugin.bat -url http://xxx/xxx -install elasticsearch-security-plugin


<h3>Configuration</h3>

<h4>Configuration (elasticsearch.yml)</h4>
Enable the security plugin
* ``http.type:org.elasticsearch.plugins.security.http.netty.NettyHttpServerTransportModule``

Optionally enable XFF 
* ``security.http.xforwardedfor.header:X-Forwarded-For``
* ``security.http.xforwardedfor.trustedproxies:<List of proxy ip's>``
* ``security.http.xforwardedfor.enforce:false``

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
				 	"indices" :[ "testindex1,testindex2" ],
				 	"permission" : "READWRITE"
			 	},
			 	
			 	{
				 	"hosts" : [ "81.*.8.*,2.44.12.14,*google.de,192.168.*.*" ],
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
				 	"indices" :[ "testindex1,testindex2" ],
				 	"fields" : "name,user,_id"
			 	},
			 	
			 	{
				 	"hosts" : [ "132.*.6.*,122.44.123.14,*google.de,192.168.1.*" ],
				 	"indices" :[ "testindex1,textindex3,myindex" ],
				 	"fields" : "timestamp,my.field.name,street,plz"
			 	}
			 ]		 		 
}'</code></pre>

Fields:
* List of fields (comma separated) which will be returned for a POST _search/_msearch query
