/**
 * 
 */
package com.tigase.auth.jwt;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;


/**
 * @author zgoda
 *
 */
public class JwtSaslServerFactory implements SaslServerFactory {

	private static final Logger log = Logger.getLogger(JwtSaslServerFactory.class.getName());
	private static JWT jwt;
	/* (non-Javadoc)
	 * @see javax.security.sasl.SaslServerFactory#createSaslServer(java.lang.String, java.lang.String, java.lang.String, java.util.Map, javax.security.auth.callback.CallbackHandler)
	 */
	@Override
	public SaslServer createSaslServer(final String mechanism, String protocol, String serverName,
			Map<String, ?> props, CallbackHandler callbackHandler) throws SaslException {
		log.config("Creating instance of SASL: " + mechanism);
		if (mechanism.equals("PLAIN")) {
			if(jwt==null){
				String type = (String)props.get("jwt-type");
				if(type==null)type = "jceks";
				String path = (String)props.get("jwt-path");
				char[] password = ((String)props.get("jwt-pwd")).toCharArray();
				try{
					KeyStore ks = KeyStore.getInstance(type);
					try(InputStream in = new FileInputStream(path)){
						ks.load(in, password);
					}catch(IOException e){
						throw new SaslException(path +" not found",e);
					}
					jwt = new JWT(ks, password);
				}catch(KeyStoreException | CertificateException |NoSuchAlgorithmException e){
					throw new SaslException("key store type "+type,e);
				}
			}
			return new SaslJwt(jwt,props, callbackHandler);
		} else
			throw new SaslException("Mechanism not supported.");
	}

	/* (non-Javadoc)
	 * @see javax.security.sasl.SaslServerFactory#getMechanismNames(java.util.Map)
	 */
	@Override
	public String[] getMechanismNames(Map<String, ?> arg0) {
		return new String[] { "PLAIN" };
	}

}
