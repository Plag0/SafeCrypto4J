package com.exceptionalhandlers.safecrypto.integrity;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class HmacIntegrity {
  private static final SecureRandom secureRandom = new SecureRandom();

  private HmacIntegrity() {
    // This class shouldn't be instantiated.
  }

  public enum Algorithm {
    SHA256,
    SHA384,
    SHA512,
  }

  private static String algorithmStringName(Algorithm algorithm) {
    switch (algorithm) {
      case SHA256:
        return "HmacSHA256";
      case SHA384:
        return "HmacSHA384";
      case SHA512:
        return "HmacSHA512";
    }
    throw new IllegalArgumentException("Unknown Algorithm value.");
  }

  private static int algorithmTagLength(Algorithm algorithm) {
    switch (algorithm) {
      case SHA256:
        return 32;
      case SHA384:
        return 48;
      case SHA512:
        return 64;
    }
    throw new IllegalArgumentException("Unknown Algorithm value.");
  }

  /**
   * A protected key for HMAC signing.
   *
   * <p>Call close when the key isn't needed any more.
   */
  public static final class Key {
    public static final int KEY_LENGTH_MIN = 32;

    private byte[] material;
    private boolean closed;

    private Key(byte[] material) {
      this.material = material.clone();
    }

    /**
     * Creates an HMAC key from raw key material.
     *
     * <p>KEY_LENGTH_MIN is enforced here.
     */
    public static Key of(byte[] keyMaterial) {
      Objects.requireNonNull(keyMaterial, "keyMaterial");

      if (keyMaterial.length < KEY_LENGTH_MIN) {
        throw new IllegalArgumentException("HMAC keys must contain at least 32 bytes");
      }

      return new Key(keyMaterial);
    }

    /**
     * Extracts key material.
     *
     * <p>Ensure that you clear these bytes after you're done with them.
     */
    public byte[] copyMaterial() {
      if (this.closed) {
        throw new IllegalStateException("HMAC key has been closed");
      }

      return material.clone();
    }

    public void close() {
      if (!this.closed) {
        Arrays.fill(material, (byte) 0);
        this.closed = true;
      }
    }
  }

  /** Securely generates a random key. */
  public static Key generateKey() {
    byte[] key = new byte[32];

    try {
      secureRandom.nextBytes(key);
      return Key.of(key);
    } finally {
      Arrays.fill(key, (byte) 0);
    }
  }

  /**
   * Computes an HMAC tag based on some data (message).
   *
   * @return a newly allocated HMAC tag.
   */
  public static byte[] sign(Algorithm algorithm, Key key, byte[] message) {
    Objects.requireNonNull(algorithm, "algorithm");
    Objects.requireNonNull(key, "key");
    if (message == null) message = new byte[0];

    byte[] keyBytes = key.copyMaterial();

    try {
      Mac mac = newMac(algorithm, keyBytes);
      return mac.doFinal(message);
    } finally {
      Arrays.fill(keyBytes, (byte) 0);
    }
  }

  /**
   * Verifies an HMAC tag.
   *
   * @return true only if the tag is valid and has the expected length
   */
  public static boolean verify(Algorithm algorithm, Key key, byte[] message, byte[] expectedTag) {

    Objects.requireNonNull(algorithm, "algorithm");
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(expectedTag, "expectedTag");

    if (expectedTag.length != algorithmTagLength(algorithm)) {
      return false;
    }

    byte[] actualTag = sign(algorithm, key, message);

    return MessageDigest.isEqual(actualTag, expectedTag);
  }

  private static Mac newMac(Algorithm algorithm, byte[] keyBytes) {
    try {
      Mac mac = Mac.getInstance(algorithmStringName(algorithm));
      mac.init(new SecretKeySpec(keyBytes, algorithmStringName(algorithm)));
      return mac;
    } catch (GeneralSecurityException e) {
      // the javax.crypto.Mac docs say that the runtime must support at least:
      // - HmacMD5
      // - HmacSHA1
      // - HmacSHA256
      // This module won't use MD5 or SHA1, so the safe default is SHA256.
      throw new IllegalStateException(
          "Required HMAC algorithm is unavailable: " + algorithmStringName(algorithm), e);
    }
  }
}
