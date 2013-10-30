elasticsearch-security-plugin
=============================
This plugins adds security functionality to elasticsearch in kind of separate modules.

As of now two security modules are implemented:
* Restrict actions against elasticsearch on IP-Address basis
* Limit fields which will be returned on IP-Address basis


Installation:
plugin.bat -url http://xxx/xxx -install elasticsearch-security-plugin

Configuration (elasticsearch.yml):
* Enable the security plugin
** ``http.type:org.elasticsearch.plugins.security.http.netty.NettyHttpServerTransportModule´´
* Optionally enable XFF 
** ``security.http.xforwardedfor.header:X-Forwarded-For´´
** ``security.http.xforwardedfor.trustedproxies:<List of proxy ip's>´´
** ``security.http.xforwardedfor.enforce:false´´

Configuration (security rules):
The security rules for each module are stored in an index ....
Look here for configuration of the rules:

``$ curl -XPUT 'http://localhost:9200/xxx/yyy/ccc' -d '
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
			 	}
			 ]		 		 
}'´´

