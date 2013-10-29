elasticsearch-security-plugin
=============================
Add security functionality to elasticsearch.

As of now two security modules are implemented:
* Restrict actions against elasticsearch on IP Address basis
* Limit fields which will be retuned on IP Address basis


Installation:


Configuration:
Add http.type:org.elasticsearch.plugins.security.http.netty.NettyHttpServerTransportModule to elasticsearch.yml
Look here for configuration of the rules:
* https://github.com/salyh/elasticsearch-security-plugin/blob/master/src/test/java/org/elasticsearch/plugins/security/CommonTests.java
