# News/Status
This plugin is no longer maintained, if you're looking for security for elasticsearch i recommend

* [Search Guard](https://github.com/floragunncom/search-guard) - Free (and open source) plugin from floragunn UG 
* [Shield](https://www.elastic.co/products/shield) - Commercial plugin from elastic

## elasticsearch-security-plugin (Unmaintained)
### This plugin is to be considered as insecure, do not use it because its unmaintained
![Unmaintained](http://upload.wikimedia.org/wikipedia/en/thumb/5/57/Circle-style-warning.svg/200px-Circle-style-warning.svg.png)

<a href="mailto:hendrikdev22@gmail.com">E-Mail hendrikdev22@gmail.com</a><p>
<a href="https://twitter.com/hendrikdev22">Twitter @hendrikdev22</a>

This plugin adds http/rest security functionality to Elasticsearch in kind of separate modules.
Instead of Netty a embedded Tomcat 7 is used to process http/rest requests. 

Currently for user based authentication and authorization Kerberos/SPNEGO and NTLM are supported through 3rd party library waffle (only on windows servers). 
For UNIX servers Kerberos/SPNEGO is supported through tomcat build in SPNEGO Valve (Works with any Kerberos implementation. For authorization either Active Directory and generic LDAP is supported).
PKI/SSL client certificate authentication is also supported (CLIENT-CERT method). SSL/TLS is also supported without client authentication.

You can use this plugin also without Kerberos/NTLM/PKI but then only host based authentication is available.

As of now two security modules are implemented:
* Actionpathfilter: Restrict actions against Elasticsearch on a coarse-grained level like who is allowed to to READ, WRITE or even ADMIN rest api calls
* Document level security (dls): Restrict actions on document level like who is allowed to query for which fields within a document

<h3>Compatibility Matrix</h3> 
| Operating System | Kerberos | LDAP  |
| ------ | ------ | ------ |
|  Windows  |  AD with waffle; MIT, Heimdal with tomcatspnego  |   AD, OpenLDAP, Domino, ...  |
|  Non-Windows  |  MIT, Heimdal with tomcatspnego  |   AD, OpenLDAP, Domino, ...  |


<h3>Installation</h3> 
(Until the first release is out you have to build this plugin yourself with maven or download from the github release page and install manually)

Branches:
* master for Elasticsearch 1.2.0 - 1.4.x
* ea0.9 for Elasticsearch 0.90.10 - 0.90.x

Prerequisites:
* Open JDK 7 or Oracle 7 JRE
* Elasticsearch 0.90.10 or higher
* If Kerberos is used you need an KDC like  AD, MIT or Heimdal

Build yourself:
* Install maven
* execute ``mvn clean package -DskipTests=true`` 

Windows:
``plugin.bat --url http://... --install elasticsearch-security-plugin-0.0.1.Beta2``

UNIX:
``plugin --url http://... --install elasticsearch-security-plugin-0.0.2.Beta2``



<h3>Configuration</h3>

<h4>Configuration (elasticsearch.yml)</h4>
Enable the security plugin
* ``http.type: org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerTransportModule`` (for ES <= 1.3)
* ``http.type: org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerTransport`` (for ES >= 1.4)
* ``script.disable_dynamic: true`` Dynamic scripts are unsafe and can potentially tamper this plugin (not needed for ES 1.2 and above)
* ``http.port: 9200`` Define exactly one port, Port ranges are not permitted

Enable CORS if needed
* ``security.cors.enabled: true`` Enable or disable cross-origin resource sharing, i.e. whether a browser on another origin can do requests to Elasticsearch. Defaults to false.
* ``security.cors.allow-origin: $hostname`` Which origins to allow. Defaults to \*, i.e. any origin.
* ``security.cors.max-age: 1728000`` Browsers send a "preflight" OPTIONS-request to determine CORS settings. Defines how long the result should be cached for. Defaults to 1728000 (20 days).
* ``security.cors.allow-methods: "OPTIONS, HEAD, GET, POST, PUT, DELETE"`` Which methods to allow. Defaults to "OPTIONS, HEAD, GET, POST, PUT, DELETE"
* ``security.cors.allow-headers: "X-Requested-With, Content-Type, Content-Length, X-HTTP-Method-Override, Origin, Accept, Authorization"`` Which headers to allow. Defaults to "X-Requested-With, Content-Type, Content-Length, X-HTTP-Method-Override, Origin, Accept, Authorization".
* ``security.cors.allow-credentials: true`` Whether the Access-Control-Allow-Credentials header should be returned. Note: This header is only returned, when the setting is set to true. Defaults to false.

Setup Kerberos
* ``security.kerberos.mode: waffle|spnegoad|none`` Kerberos implementation (spnegoad is tomcat-built in Kerberos/SPNEGO support)

If you use spnegoad then you must provide the following configuration parameters:
* ``security.authorization.ldap.ldapurls: ldap://myldaphost:389`` Ldap Servers (you can configure a fallback by adding a comma separated second ldap url. This would then be used as tomcats alternateURL)
* ``security.kerberos.login.conf.path: c:\path\to\login.conf`` JAAS login modules configuration
* ``security.kerberos.krb5.conf.path: /path/to/krb5.conf`` Kerberos configuration file
* ``security.authorization.ldap.connectionname: uid=admin,ou=system`` Low priv login to ldap server (Omit for anonymous authentication).
* ``security.authorization.ldap.connectionpassword: secret`` Password for low priv login to ldap server (Omit for anonymous authentication). No encryption here, this is plaintext!

If you use spnegoad and not Active Directory you may want configure your LDAP layout
(look here for details: http://tomcat.apache.org/tomcat-7.0-doc/realm-howto.html#JNDIRealm)
* ``security.authorization.ldap.userbase: ""`` (Default is Root DSE)
* ``security.authorization.ldap.usersearch: (sAMAccountName={0})`` Default is (sAMAccountName={0})
* ``security.authorization.ldap.rolebase: ""`` (Default is Root DSE)
* ``security.authorization.ldap.rolesearch: (member={0})`` Default is (member={0})
* ``security.authorization.ldap.rolename: cn`` (Default is cn)

Optionally enable SSL/TLS
* ``security.ssl.enabled: true`` Enable SSL
* ``security.ssl.keystorefile: /path/to/keystore`` Keystore for private and public server certificates
* ``security.ssl.keystorepass: changeit`` Password for the keystore
* ``security.ssl.keystoretype: JKS`` Keystoretype (either JKS or PKCS12)

If SSL is enabled you can use PKI/Client certificates for authentication
* ``security.ssl.clientauth.enabled: true`` Enable PKI/Client certificates for authentication
* ``security.ssl.clientauth.truststorefile: /path/to/truststore`` Keystore (truststore) for public client certificates which the server should trust
* ``security.ssl.clientauth.truststorepass: changeit`` Password for the truststore
* ``security.ssl.clientauth.truststoretype: JKS`` (either JKS or PKCS12)
* ``security.ssl.userattribute: CN`` Name of the attribute from the client certificate user name which denotes the username for further authentication/authorization

Optionally enable XFF 
* ``security.http.xforwardedfor.header: X-Forwarded-For`` Enable XFF
* ``security.http.xforwardedfor.trustedproxies: <List of proxy ip's>`` Example: "192.168.1.1,31.122.45.1,193.54.55.21"
* ``security.http.xforwardedfor.enforce: true`` Enforce XFF header, default: false

Enable at least one of the two security modules 
* ``security.module.actionpathfilter.enabled: true``
* ``security.module.dls.enabled: true`` Note: DLS is an early development stage and considered to be "alpha"

Enable strict mode if really needed (disabled by default, enable only if you know what you are doing)
* ``security.strict: true`` Strict mode currently deny facet and suggester responses and treat some command like _mapping or _analyze as sensitive write requests 


<h4>Configuration (security rules)</h4>
The security rules for each module are stored in an special index ``securityconfiguration``.
For security reasons you can access this index only from localhost (127.0.0.1).

<b>Example: Configure 'Restrict actions against elasticsearch on IP-Address only basis (actionpathfilter)' module. This work's without Kerberos/NTLM but maybe require XFF to be configured properly.</b>
<pre><code>$ curl -XPUT 'http://localhost:9200/securityconfiguration/actionpathfilter/actionpathfilter' -d '
{
			 "rules": [
			 	{
				 	"permission" : "ALL"
			 	},
			 	
			 	{
				 	"hosts" : [ "google-public-dns-a.google.com" ],
				 	"indices" : [ "*"],
				 	"types" : [ "twitter","facebook" ],
				 	"permission" : "NONE"
			 	},
			 	
			 	{
				 	"hosts" : [ "8.8.8.8" ],
				 	"indices" : [ "testindex1","testindex2" ],
				 	"types" : [ "*" ],
				 	"permission" : "READWRITE"
			 	},
			 	
			 	{
				 	"hosts" : [ "81.*.8.*","2.44.12.14","*google.de","192.168.*.*" ],
				 	"indices" : [ "testindex1" ],
				 	"types" : [ "quotes" ],
				 	"permission" : "READONLY"
			 	}
			 ]		 		 
}'</code></pre>

<b>Example: Configure 'Restrict actions against elasticsearch on user/role and ip/hostname basis (actionpathfilter)' module. This needs Kerberos/NTLM.</b>
<pre><code>$ curl -XPUT 'http://localhost:9200/securityconfiguration/actionpathfilter/actionpathfilter' -d '
{
			 "rules": [
			 	{
			 		
				 	"users" : [ "*" ],
				 	"roles" : [ "*" ],
				 	"hosts" : [ "*" ],
				 	"indices" : [ "*" ],
				 	"types" : [ "*" ],
				 	"permission" : "ALL"
			 	},
			 	
			 	{
			 		"users" : [ "spock","kirk" ],
				 	"roles" : [ "admin" ],
				 	"hosts" : [ "*" ],
				 	"indices" : [ "*"],
				 	"types" : [ "twitter","facebook" ],
				 	"permission" : "NONE"
			 	},
			 	
			 	{
			 	
			 		"users" : [ "bowna" ],
				 	"roles" : [ "*" ],
				 	"hosts" : [ "*" ],
				 	"indices" : [ "testindex1","testindex2" ],
				 	"types" : [ "*" ],
				 	"permission" : "READWRITE"
			 	},
			 	
			 	{
			 		"users" : [ "smithf","salyh" ],
				 	"roles" : [ "users","guests" ],
				 	"hosts" : [ "81.*.8.*","2.44.12.14","*google.de","192.168.*.*" ],
				 	"indices" : [ "testindex1" ],
				 	"types" : [ "quotes" ],
				 	"permission" : "READONLY"
			 	}
			 ]		 		 
}'</code></pre>


Permissions:
* ALL: No restrictions
* READWRITE: No admin actions but read write operations allowed (for example _settings, _status, _cluster)
* READONLY: No admin and no write actions allowed (but read actions) (for example _update, _bulk, _mapping)
* NONE: No action allowed (also read actions will be denied) (even _search and _msearch are denied)

In a more formal way the configuration looks like:

* Format is JSON
* One top level array named "rules"
* The single wildchar character (\*) match any user, role, host, type or any index
* In hostnames or ip's you can use the wildcard character (\*) for specifying subnets
* The rules elemens look like:

<pre><code>


			 	{
			 		"users" : [ &lt;* or list of users/principals for which this rule apply&gt; ],
			 		"roles" : [ &lt;* or list of AD roles for which this rule apply&gt; ],
				 	"hosts" : [ &lt;* or list of hostnames/ip's for which this rule apply&gt; ],
				 	"types" :[ &lt;* or list of types for which this rule apply&gt; ],
				 	"indices" :[ &lt;* or list of indices for which this rule apply&gt; ],
				 	"permission" : "ALL"&#448;"READWRITE"&#448;"READONLY"&#448;"NONE";
			 	}
			 	
</code></pre>
 
* There must be exactly one default rule:

<pre><code>


			 	{
				 	
				 	"&lt;qualification name\>" : &lt;qualification string&gt;
			 	}
			 	
</code></pre>

* If more than one rule match then the first one (right down at the top of the security config) is used


<b>Example: Configure 'Limit fields which will be returned on IP-Address basis (document level security)' module</b>
This work a little bit different then the actionpathfilter. First you have to configure a default for all documents which do not contain document level security informations. 
<pre><code>$ curl -XPUT 'http://localhost:9200/securityconfiguration/dlspermissions/default' -d '
{
			 "dlspermissions":
				{
					"*" : 
									{
										"read" :["dlstoken1","t_powerusers","t_office","t_admin"],
										"update" : ["t_office","t_admin"],
										"delete" : []
									}
					
													
				}				 
}'</code></pre>
The above means that every field ("*") in a document which has document level security associated can be read by those who have obtained one of the listed dls tokens (in this example: "dlstoken1","t_powerusers","t_office","t_admin"),
every field can be updated by those with the tokens "t_office","t_admin" and every field can be deleted by no one (empty token array).

Another example could be:
<pre><code>$ curl -XPUT 'http://localhost:9200/securityconfiguration/dlspermissions/default' -d '
{
			 "dlspermissions":
				{
					"*" : 
									{
										"read" :["t_admin"],
										"update" : [],
										"delete" : []
									},
									
					"qoutes.account.*" : 
									{
										"read" :["t_office","t_admin"],
										"update" : ["t_office","t_admin"],
										"delete" : []
									},
									
					"customers.*" : 
									{
										"read" :["*"],
										"update" : ["*"],
										"delete" : ["*"]
									}
					
													
				}				 
}'</code></pre>
The above means that every field ("*") in a document which has document level security associated can be read by those who have obtained the "t_admin" token. Updates and deletes are not permitted.
All fields matching "qoutes.account.*" can be read and updated by those who have obtained the "t_office" or "t_admin" token.
All fields matching "customers.*" can be read, updated and deleted by any one.

If a document contains document level security information those will be applied instead of the default. An example for such a document could be:
<pre><code>$ curl -XPUT 'http://localhost:9200/finacial/qoutes/Id-12345' -d '
{

			"company" : "Hewlett Packard",
			"street" : "Packard Bell Road 1",
			"zip" : "12345",
			
			
			"customers":{
							"Apple":{
										"street" : "infinite loop"
									},
									
							"Microsoft":{
										"street" : "One Microsoft Way"
									}
			
						}
			
			
			"qoutes": {
						"quoteid" : "QO-7776-U",
						"amount" : 300000,
						"account" : {
										"name" : "Demo Ltd.",
										"classification" : "A",
										"tickersymbol" : "AAOL"
									}
					}	



			 "dlspermissions":
				{
					"*" : 
									{
										"read" :["t_admin"],
										"update" : [],
										"delete" : []
									},
									
					"qoutes.account.*" : 
									{
										"read" :["t_office","t_admin"],
										"update" : ["t_office","t_admin"],
										"delete" : []
									},
									
					"customers.*" : 
									{
										"read" :["*"],
										"update" : ["*"],
										"delete" : ["*"]
									}
					
													
				}
				
				
				
							 
}'</code></pre>

How to obtain a dls (document level security) token? It works very similar to the actionpathfilter:
<pre><code>$ curl -XPUT 'http://localhost:9200/securityconfiguration/dlspermissions/dlspermissions' -d '
{
			 "rules": [
			 	{
			 		
				 	"users" : [ "*" ],
				 	"roles" : [ "*" ],
				 	"hosts" : [ "*" ],
				 	"indices" : [ "*" ],
				 	"types" : [ "*" ],
				 	"dlstoken" : [ ]
			 	},
			 	
			 	{
			 		"users" : [ "spock","kirk" ],
				 	"roles" : [ "admin" ],
				 	"hosts" : [ "*" ],
				 	"indices" : [ "*"],
				 	"types" : [ "twitter","facebook" ],
				 	"dlstoken" : [ "t_office","t_admin" ]
			 	},
			 	
			 	{
			 	
			 		"users" : [ "bowna" ],
				 	"roles" : [ "*" ],
				 	"hosts" : [ "*" ],
				 	"indices" : [ "testindex1","testindex2" ],
				 	"types" : [ "*" ],
				 	"dlstoken" : [ "t_office","t_admin" ]
			 	},
			 	
			 	{
			 		"users" : [ "smithf","salyh" ],
				 	"roles" : [ "users","guests" ],
				 	"hosts" : [ "81.*.8.*","2.44.12.14","*google.de","192.168.*.*" ],
				 	"indices" : [ "testindex1" ],
				 	"types" : [ "quotes" ],
				 	"dlstoken" : [ "t_office","t_admin" ]
			 	}
			 ]		 		 
}'</code></pre>


Who i am:<br>
"users" : [...], if * or not present match always, if empty match always, OR<br>
"roles" : [...], if * or not present match always, if empty match always, OR<br>
"hosts" : [...], if * or not present match always, if empty match always, OR<br>
<br><br>
On what i am operating<br>
"indices" : [...], if * or not present match always, if empty match always, OR<br>
"types": [...], if * or not present match always, if empty match always, OR<br>
<br><br>
What i am allowed to do/see/whatever when above match, if so then stop here and do not evaluate other rules (first one wins)<br>
"permission" : "READWRITE"<br>

All present attributes (users, roles, hosts, indices, types) must match, if not this rule will not be applied and the next one is evaluated.
If no rule matches the default rule will be applied.<br><br>
"users" : [u1,u2]<br>
"roles" : [role1, role2]<br>
"hosts" : [host1, host2]<br>
<br><br>
"indices" : [i1,i2]<br>
"types": [t1, t2]<br>
<br><br>
This rule match if (the user is u1 or u2) and (has the role rol1 or role2) <br>
and (issues the request from host1 or host2) and (operates on i1 or i2 or both)<br>
and uses (documents of types t1 or t2 or both)<br>



<h3>elasticsearch-security-plugin for Kibana</h3>

Ram Kotamaraja provided some enhancements to make the plugin work with Kibana 3.
For details see https://github.com/rkotamaraja/elasticsearch-security-plugin/commits/master and https://github.com/salyh/elasticsearch-security-plugin/pull/5 
Here is the documentation for this:

Added a new security index to provide security around kibana 3.0.0 fifth milestone. Kibana uses a generic search query such as http://elasticsearchhost:9200/testindex1/_search. To provide security around queries like that, the plugin is modified to support additional kibana configuration. Configuration is as follows. 

<pre><code>
PUT /securityconfiguration/actionpathfilter/kibana
{
             "rules": [
                {
                    "index" : "testindex1",
                    "types" : [ "testtype1", "testtype5", "testtype13", "testtype7"]
                },
                {
                    "index" : "testindex2",
                    "types" : [ "testtype19", "testtype21" ]
                },
                {
                    "index" : "testdata",
                    "types" : [ ""testtype1", "testtype2" ]
                }
	     ]
}

</code></pre>

This configuration allows users to specify which types in a given index are accessible by users. 

<h3>Contributers</h3>
* Ram Kotamaraja (https://github.com/rkotamaraja)

<p>
<p>
TODO<br>
* http://tomcat.apache.org/tomcat-7.0-doc/api/org/apache/catalina/valves/RemoteIpValve.html
* Check restict highlighting http://www.elasticsearch.org/guide/en/elasticsearch/reference/current/search-request-highlighting.html
* Enforce script.disable_dynamic: true
* Check restrict bulk requests and responses
* Add "at least authenticated" user rule
* Provide rest api endpoint for displaying current security rules/status

<h3>License</h3>
Copyright 2013-2014 Hendrik Saly

Unless required by applicable law or agreed to in writing, Licensor provides the Work (and each Contributor provides its Contributions) 
on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied, including, without limitation, any warranties or 
conditions of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE. You are solely responsible for determining the 
appropriateness of using or redistributing the Work and assume any risks associated with Your exercise of permissions under this License.

Limitation of Liability. In no event and under no legal theory, whether in tort (including negligence), contract, or otherwise, unless 
required by applicable law (such as deliberate and grossly negligent acts) or agreed to in writing, shall any Contributor be liable to 
You for damages, including any direct, indirect, special, incidental, or consequential damages of any character arising as a result of 
this License or out of the use or inability to use the Work (including but not limited to damages for loss of goodwill, work stoppage, 
computer failure or malfunction, or any and all other commercial damages or losses), even if such Contributor has been advised of the 
possibility of such damages.

Licensed under the "No License" license (github default): 
http://choosealicense.com/licenses/no-license/

