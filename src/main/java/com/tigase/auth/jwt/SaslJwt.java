/**
 * 
 */
package com.tigase.auth.jwt;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;

import org.json.JSONObject;

import tigase.auth.XmppSaslException;
import tigase.auth.XmppSaslException.SaslError;
import tigase.auth.mechanisms.AbstractSasl;

/**
 * @author zgoda
 *
 */
public class SaslJwt extends AbstractSasl {
	
	private static final String MECHANISM = "PLAIN";
	
	private JWT jwt;
	protected SaslJwt(JWT jwt,Map<? super String, ?> props,
			CallbackHandler callbackHandler) {
		super(props, callbackHandler);
		this.jwt = jwt;
	}

	/* (non-Javadoc)
	 * @see javax.security.sasl.SaslServer#evaluateResponse(byte[])
	 */
	@Override
	public byte[] evaluateResponse(byte[] response) throws SaslException {
		if (response != null && response.length > 0) {
			try{
				String[] data = split(response, "");
				final String authzid = data[0];
				final String authcid = data[1];
				final String passwd = data[2];
				JSONObject payload = jwt.verify(passwd);
				authorizedId = payload.getString("sub");
				complete = true;
				return null;
			}catch(RuntimeException e){
				
			}
		}
		throw new XmppSaslException(SaslError.not_authorized);
	}

	/* (non-Javadoc)
	 * @see javax.security.sasl.SaslServer#getAuthorizationID()
	 */
	@Override
	public String getAuthorizationID() {
		return authorizedId;
	}

	/* (non-Javadoc)
	 * @see javax.security.sasl.SaslServer#getMechanismName()
	 */
	@Override
	public String getMechanismName() {
		return MECHANISM;
	}

	/* (non-Javadoc)
	 * @see javax.security.sasl.SaslServer#unwrap(byte[], int, int)
	 */
	@Override
	public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
		return null;
	}

	/* (non-Javadoc)
	 * @see javax.security.sasl.SaslServer#wrap(byte[], int, int)
	 */
	@Override
	public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
		return null;
	}
}
