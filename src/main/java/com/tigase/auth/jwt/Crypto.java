package com.tigase.auth.jwt;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.Mac;

/**
 * Internal common interface for all crypto algorithms.
 * This is just an utility in order to simplfy sign and verify operations.
 *
 * @author Paulo Lopes
 */
public interface Crypto {
  byte[] sign(byte[] payload);

  boolean verify(byte[] signature, byte[] payload);
}

/**
 * MAC based Crypto implementation
 * @author Paulo Lopes
 */
final class CryptoMac implements Crypto {
  private final Mac mac;

  CryptoMac(final Mac mac) {
    this.mac = mac;
  }

  @Override
  public synchronized byte[] sign(byte[] payload) {
    return mac.doFinal(payload);
  }

  @Override
  public boolean verify(byte[] signature, byte[] payload) {
    return Arrays.equals(signature, sign(payload));
  }
}

/**
 * Public Key based Crypto implementation
 * @author Paulo Lopes
 */
final class CryptoPublicKey implements Crypto {
  private final Signature sig;
  private final PublicKey publicKey;

  CryptoPublicKey(final String algorithm, final PublicKey publicKey) {
    this.publicKey = publicKey;

    Signature signature;
    try {
      // use default
      signature = Signature.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      // error
      throw new RuntimeException(e);
    }

    this.sig = signature;
  }

  @Override
  public synchronized byte[] sign(byte[] payload) {
    throw new RuntimeException("CryptoPublicKey cannot sign");
  }

  @Override
  public synchronized boolean verify(byte[] signature, byte[] payload) {
    try {
      sig.initVerify(publicKey);
      sig.update(payload);
      return sig.verify(signature);
    } catch (SignatureException | InvalidKeyException e) {
      throw new RuntimeException(e);
    }
  }
}

/**
 * Public Key based Crypto implementation
 * @author Paulo Lopes
 */
final class CryptoPrivateKey implements Crypto {
  private final Signature sig;
  private final PrivateKey privateKey;

  CryptoPrivateKey(final String algorithm, final PrivateKey privateKey) {
    this.privateKey = privateKey;

    Signature signature;
    try {
      // use default
      signature = Signature.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      // error
      throw new RuntimeException(e);
    }

    this.sig = signature;
  }

  @Override
  public synchronized byte[] sign(byte[] payload) {
    try {
      sig.initSign(privateKey);
      sig.update(payload);
      return sig.sign();
    } catch (SignatureException | InvalidKeyException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public synchronized boolean verify(byte[] signature, byte[] payload) {
    throw new RuntimeException("CryptoPrivateKey cannot verify");
  }
}

/**
 * Signature based Crypto implementation
 * @author Paulo Lopes
 */
final class CryptoSignature implements Crypto {
  private final Signature sig;
  private final PrivateKey privateKey;
  private final X509Certificate certificate;

  CryptoSignature(final String algorithm, final X509Certificate certificate, final PrivateKey privateKey) {
    this.certificate = certificate;
    this.privateKey = privateKey;

    Signature signature;
    try {
      // use default
      signature = Signature.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      // fallback
      try {
        signature = Signature.getInstance(certificate.getSigAlgName());
      } catch (NoSuchAlgorithmException e1) {
        // error
        throw new RuntimeException(e);
      }
    }

    this.sig = signature;
  }

  @Override
  public synchronized byte[] sign(byte[] payload) {
    try {
      sig.initSign(privateKey);
      sig.update(payload);
      return sig.sign();
    } catch (SignatureException | InvalidKeyException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public synchronized boolean verify(byte[] signature, byte[] payload) {
    try {
      sig.initVerify(certificate);
      sig.update(payload);
      return sig.verify(signature);
    } catch (SignatureException | InvalidKeyException e) {
      throw new RuntimeException(e);
    }
  }
}

final class CryptoNone implements Crypto {
  private static final byte[] NOOP = new byte[0];

  @Override
  public byte[] sign(byte[] payload) {
      return NOOP;
    }

  @Override
  public boolean verify(byte[] signature, byte[] payload) {
      return true;
    }
}