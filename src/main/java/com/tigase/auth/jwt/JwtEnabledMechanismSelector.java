package com.tigase.auth.jwt;

import javax.security.sasl.SaslServerFactory;

import tigase.auth.DefaultMechanismSelector;
import tigase.xmpp.XMPPResourceConnection;

public class JwtEnabledMechanismSelector extends DefaultMechanismSelector {

	protected boolean match(SaslServerFactory factory, String mechanismName, XMPPResourceConnection session) {
		boolean result = super.match(factory, mechanismName, session);
		if (!result && (factory instanceof JwtSaslServerFactory)) {
			return true;
		}
		return result;
	}
	
}
