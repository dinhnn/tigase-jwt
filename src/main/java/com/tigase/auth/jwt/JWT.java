package com.tigase.auth.jwt;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;

import org.json.JSONObject;

public class JWT {
	private final Map<String, Crypto> cryptoMap;

	/**
	 * Creates a new Message Authentication Code
	 *
	 * @param keyStore
	 *          a valid JKS
	 * @param alias
	 *          algorithm to use e.g.: HmacSHA256
	 * @return Mac implementation
	 */
	private Mac getMac(final KeyStore keyStore, final char[] keyStorePassword, final String alias) {
		try {
			final Key secretKey = keyStore.getKey(alias, keyStorePassword);

			// key store does not have the requested algorithm
			if (secretKey == null) {
				return null;
			}

			Mac mac = Mac.getInstance(secretKey.getAlgorithm());
			mac.init(secretKey);

			return mac;
		} catch (NoSuchAlgorithmException | InvalidKeyException | UnrecoverableKeyException | KeyStoreException e) {
			throw new RuntimeException(e);
		}
	}

	public JWT(final KeyStore keyStore, final char[] keyStorePassword) {

		Map<String, Crypto> tmp = new HashMap<>();

		for (String alg : Arrays.asList("HS256", "HS384", "HS512")) {
			try {
				Mac mac = getMac(keyStore, keyStorePassword, alg);
				if (mac != null) {
					tmp.put(alg, new CryptoMac(mac));
				}
			} catch (RuntimeException e) {
				e.printStackTrace();
			}
		}

		// load SIGNATUREs
		final Map<String, String> alias = new HashMap<>();
		alias.put("RS256", "SHA256withRSA");
		alias.put("RS384", "SHA384withRSA");
		alias.put("RS512", "SHA512withRSA");
		alias.put("ES256", "SHA256withECDSA");
		alias.put("ES384", "SHA384withECDSA");
		alias.put("ES512", "SHA512withECDSA");

		for (String alg : Arrays.asList("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")) {
			try {
				X509Certificate certificate = getCertificate(keyStore, alg);
				PrivateKey privateKey = getPrivateKey(keyStore, keyStorePassword, alg);
				if (certificate != null && privateKey != null) {
					tmp.put(alg, new CryptoSignature(alias.get(alg), certificate, privateKey));
				} else {
				}
			} catch (RuntimeException e) {
				e.printStackTrace();
			}
		}
	
		cryptoMap=Collections.unmodifiableMap(tmp);

	}

	private X509Certificate getCertificate(final KeyStore keyStore, final String alias) {
		try {
			return (X509Certificate) keyStore.getCertificate(alias);

		} catch (KeyStoreException e) {
			throw new RuntimeException(e);
		}
	}

	private PrivateKey getPrivateKey(final KeyStore keyStore, final char[] keyStorePassword, final String alias) {
		try {
			return (PrivateKey) keyStore.getKey(alias, keyStorePassword);

		} catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
			throw new RuntimeException(e);
		}
	}

	public JSONObject verify(final String token) {
		String[] segments = token.split("\\.");
		if (segments.length != 3) {
			throw new RuntimeException("Not enough or too many segments");
		}
		// All segment should be base64
		String headerSeg = segments[0];
		String payloadSeg = segments[1];
		String signatureSeg = segments[2];

		if ("".equals(signatureSeg)) {
			throw new RuntimeException("Signature is required");
		}
		// base64 decode and parse JSON
		JSONObject header = new JSONObject(new String(Base64.getUrlDecoder().decode(headerSeg), StandardCharsets.UTF_8));
		JSONObject payload = new JSONObject(new String(Base64.getUrlDecoder().decode(payloadSeg), StandardCharsets.UTF_8));

		String alg = header.getString("alg");

		Crypto crypto = cryptoMap.get(alg);

		if (crypto == null) {
			throw new RuntimeException("Algorithm not supported");
		}
		String signingInput = headerSeg + "." + payloadSeg;

		if (!crypto.verify(Base64.getUrlDecoder().decode(signatureSeg), signingInput.getBytes(StandardCharsets.UTF_8))) {
			throw new RuntimeException("Signature verification failed");
		}
		final long now = System.currentTimeMillis() / 1000;

    if (payload.has("exp")) {
      if (now >= payload.getLong("exp")) {
      	throw new RuntimeException("Expired JWT token: exp <= now");
      }
    }
		return payload;
	}
}
