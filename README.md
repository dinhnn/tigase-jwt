tigase-jwt
============

Jwt authentication component for Tigase XMPP server.

Step 1: Client request to API Server to receive jwt token

Step 2: XMPP client login with username & token as password

Step 3: Tigase Server verify token

Config 
sess-man/plugins-conf/urn\:ietf\:params\:xml\:ns\:xmpp-sasl/factory=com.tigase.auth.jwt.JwtSaslServerFactory
