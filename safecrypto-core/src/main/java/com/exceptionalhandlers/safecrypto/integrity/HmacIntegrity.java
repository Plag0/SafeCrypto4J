package com.exceptionalhandlers.safecrypto.integrity;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Provides safe-by-default HMAC message-integrity operations.
 *
 * <p>HMAC authenticates data using a shared secret key. It provides integrity and authenticity, but
 * does not provide confidentiality or prevent replay.
 *
 * <p>Example:
 *
 * <pre>{@code
 * try (HmacIntegrity.Key key = HmacIntegrity.generateKey()) {
 *   byte[] message = "important data 👩‍❤️‍👩️".getBytes(StandardCharsets.UTF_8);
 *   byte[] tag = HmacIntegrity.sign(key, message);
 *
 *   if (!HmacIntegrity.verify(key, message, tag)) {
 *     throw new SecurityException("Invalid HMAC");
 *   }
 * }
 * }</pre>
 *
 * <p>Protections implemented:
 *
 * <ul>
 *   <li>Uses HMAC rather than an unkeyed hash for authentication.
 *   <li>Uses SHA-512 by default.
 *   <li>Allows only SHA-256, SHA-384, and SHA-512 HMAC algorithms.
 *   <li>Requires keys to contain at least 256 bits of material.
 *   <li>Copies caller-provided key material.
 *   <li>Clears internal and temporary key-material arrays when possible.
 *   <li>Compares verification tags using a constant-time comparison.
 *   <li>Rejects tags with an unexpected length before comparison.
 * </ul>
 *
 * <p>Out of scope:
 *
 * <ul>
 *   <li>Encryption or confidentiality.
 *   <li>Key storage, persistence, rotation, or distribution.
 *   <li>Replay protection, freshness, timestamps, or nonce management.
 *   <li>Canonicalization or serialization of messages.
 *   <li>Protection against compromised hosts, memory inspection, or misuse of an already-exposed
 *       key.
 * </ul>
 */
public final class HmacIntegrity {
  public static final Algorithm DEFAULT_ALGORITHM = Algorithm.SHA512;

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private HmacIntegrity() {
    // This class shouldn't be instantiated.
  }

  public enum Algorithm {
    SHA256("HmacSHA256", 32),
    SHA384("HmacSHA384", 48),
    SHA512("HmacSHA512", 64);

    private final String jcaName;
    private final int tagLengthBytes;

    Algorithm(String jcaName, int tagLengthBytes) {
      this.jcaName = jcaName;
      this.tagLengthBytes = tagLengthBytes;
    }

    String jcaName() {
      return jcaName;
    }

    int tagLengthBytes() {
      return tagLengthBytes;
    }
  }

  /**
   * A protected key for HMAC signing.
   *
   * <p>Call {@link #close()} when the key is no longer needed.
   */
  public static final class Key implements AutoCloseable {
    public static final int KEY_LENGTH_MIN = 32;

    private byte[] material;
    private boolean closed;

    private Key(byte[] material) {
      this.material = material.clone();
    }

    /**
     * Creates an HMAC key from raw key material.
     *
     * @param keyMaterial the raw key material; it is copied
     * @return a new HMAC key
     * @throws IllegalArgumentException if {@code keyMaterial} is {@code null} or if the key
     *     contains fewer than {@value #KEY_LENGTH_MIN} bytes
     */
    public static Key of(byte[] keyMaterial) {
      if (keyMaterial == null) {
        throw new IllegalArgumentException("keyMaterial must not be null");
      }

      if (keyMaterial.length < KEY_LENGTH_MIN) {
        throw new IllegalArgumentException("HMAC keys must contain at least 32 bytes");
      }

      return new Key(keyMaterial);
    }

    /**
     * Extracts key material.
     *
     * <p>Ensure that you clear these bytes after you're done with them.
     *
     * @return a copy of the key material
     * @throws IntegrityException if this key has been closed
     */
    public byte[] copyMaterial() {
      if (this.closed) {
        throw new IntegrityException("HMAC key has been closed", null);
      }

      return material.clone();
    }

    @Override
    public void close() {
      if (!this.closed) {
        Arrays.fill(material, (byte) 0);
        this.closed = true;
      }
    }
  }

  /**
   * Generates a cryptographically random HMAC key.
   *
   * @return a new randomly generated HMAC key
   */
  public static Key generateKey() {
    byte[] key = new byte[32];

    try {
      SECURE_RANDOM.nextBytes(key);
      return Key.of(key);
    } finally {
      Arrays.fill(key, (byte) 0);
    }
  }

  /**
   * Computes an HMAC tag using {@link #DEFAULT_ALGORITHM}.
   *
   * @param key the HMAC key
   * @param message the message to sign
   * @return a newly allocated HMAC tag
   * @throws IllegalArgumentException if {@code key} or {@code message} is {@code null}
   * @throws IntegrityException if the key has been closed or the required cryptographic algorithm
   *     is unavailable
   */
  public static byte[] sign(Key key, byte[] message) {
    return sign(key, message, DEFAULT_ALGORITHM);
  }

  /**
   * Computes an HMAC tag using a specific algorithm.
   *
   * @param key the HMAC key
   * @param message the message to sign
   * @param algorithm the HMAC algorithm to use
   * @return a newly allocated HMAC tag
   * @throws IllegalArgumentException if any argument is {@code null}
   * @throws IntegrityException if the key has been closed or the required cryptographic algorithm
   *     is unavailable
   */
  public static byte[] sign(Key key, byte[] message, Algorithm algorithm) {
    if (algorithm == null) {
      throw new IllegalArgumentException("algorithm must not be null");
    }
    if (key == null) {
      throw new IllegalArgumentException("key must not be null");
    }
    if (message == null) {
      throw new IllegalArgumentException("message must not be null");
    }

    byte[] keyBytes = key.copyMaterial();

    try {
      Mac mac = newMac(algorithm, keyBytes);
      return mac.doFinal(message);
    } finally {
      Arrays.fill(keyBytes, (byte) 0);
    }
  }

  /**
   * Verifies an HMAC tag using {@link #DEFAULT_ALGORITHM}.
   *
   * @param key the HMAC key
   * @param message the message to verify
   * @param expectedTag a previously signed tag to check against
   * @return {@code true} only if the tag is valid and has the expected length
   * @throws IllegalArgumentException if any argument is {@code null}, or if {@code expectedTag} is
   *     empty
   * @throws IntegrityException if the key has been closed or the required cryptographic algorithm
   *     is unavailable
   */
  public static boolean verify(Key key, byte[] message, byte[] expectedTag) {
    return verify(key, message, expectedTag, DEFAULT_ALGORITHM);
  }

  /**
   * Verifies an HMAC tag using a specific algorithm.
   *
   * <p>The tag must have been created using the same algorithm.
   *
   * @param key the HMAC key
   * @param message the message to verify
   * @param expectedTag a previously signed tag to check against
   * @param algorithm the HMAC algorithm to use
   * @return {@code true} only if the tag is valid and has the expected length
   * @throws IllegalArgumentException if any argument is {@code null}, or if {@code expectedTag} is
   *     empty
   * @throws IntegrityException if the key has been closed or the required cryptographic algorithm
   *     is unavailable
   */
  public static boolean verify(Key key, byte[] message, byte[] expectedTag, Algorithm algorithm) {
    if (algorithm == null) {
      throw new IllegalArgumentException("algorithm must not be null");
    }
    if (key == null) {
      throw new IllegalArgumentException("key must not be null");
    }
    if (expectedTag == null || expectedTag.length == 0) {
      throw new IllegalArgumentException("expectedTag must not be null or empty");
    }
    if (expectedTag.length != algorithm.tagLengthBytes()) {
      throw new IllegalArgumentException(
          "expectedTag was not the correct length for this algorithm");
    }

    byte[] actualTag = sign(key, message, algorithm);

    return MessageDigest.isEqual(actualTag, expectedTag);
  }

  private static Mac newMac(Algorithm algorithm, byte[] keyBytes) {
    try {
      Mac mac = Mac.getInstance(algorithm.jcaName());
      mac.init(new SecretKeySpec(keyBytes, algorithm.jcaName()));
      return mac;
    } catch (GeneralSecurityException e) {
      // the javax.crypto.Mac docs say that the runtime must support at least:
      // - HmacMD5
      // - HmacSHA1
      // - HmacSHA256
      throw new IntegrityException(
          "Required HMAC algorithm is unavailable: " + algorithm.jcaName(), e);
    }
  }
}
