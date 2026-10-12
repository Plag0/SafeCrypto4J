package com.exceptionalhandlers.safecrypto.integrity;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Signs and verifies messages using HMAC, a keyed hash that proves data has not been altered.
 *
 * <p>HMAC authenticates data using a shared secret key. It provides integrity and authenticity, but
 * not confidentiality: the message itself is not hidden. Use {@code AesEncryptor} when the data
 * must also be kept secret.
 *
 * <pre>{@code
 * try (HmacIntegrity.Key key = HmacIntegrity.generateKey()) {
 *   byte[] message = "important data".getBytes(StandardCharsets.UTF_8);
 *   byte[] tag = HmacIntegrity.sign(key, message);
 *
 *   if (!HmacIntegrity.verify(key, message, tag)) {
 *     throw new SecurityException("Invalid HMAC");
 *   }
 * }
 * }</pre>
 *
 * <p>Tags are raw bytes. Encode them (for example with Base64) to store them as text, and verify
 * with the same algorithm they were signed with, because a tag does not record its algorithm.
 *
 * <h2>Protections</h2>
 *
 * <ul>
 *   <li>Forgery, prevented by a keyed construction rather than a plain hash
 *   <li>Weak algorithms, prevented by allowing only HMAC with SHA-256, SHA-384 or SHA-512
 *   <li>Short keys, rejected below {@value Key#KEY_LENGTH_MIN} bytes
 *   <li>Timing attacks, prevented by constant-time tag comparison
 *   <li>Truncated tags, rejected by requiring the algorithm's full tag length
 *   <li>Key retention in JVM memory, reduced by clearing key material when a key is closed
 * </ul>
 *
 * <h2>Out of scope</h2>
 *
 * <ul>
 *   <li>Confidentiality. Encrypt the data if it must be kept secret.
 *   <li>Key management. Callers must store, distribute and rotate keys securely.
 *   <li>Replay. A valid message and tag can be resent; include a timestamp or counter in the
 *       message if that matters.
 *   <li>Canonicalisation. The caller decides how a message is serialised to bytes, and must do so
 *       the same way when signing and verifying.
 *   <li>Host compromise. An attacker controlling the JVM can read keys in memory, including copies
 *       held by the Java crypto provider.
 * </ul>
 */
public final class HmacIntegrity {

  /**
   * Algorithm used when none is given. Tags must be verified with the algorithm that signed them.
   */
  public static final Algorithm DEFAULT_ALGORITHM = Algorithm.SHA512;

  /** RFC 2104 recommends keys at least as long as the hash output: 64 bytes for SHA-512. */
  private static final int GENERATED_KEY_LENGTH_BYTES = 64;

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  // Non-instantiable utility class.
  private HmacIntegrity() {}

  /** The HMAC algorithms this library allows. */
  public enum Algorithm {
    /** HMAC-SHA256, producing 32-byte tags. */
    SHA256("HmacSHA256", 32),
    /** HMAC-SHA384, producing 48-byte tags. */
    SHA384("HmacSHA384", 48),
    /** HMAC-SHA512, producing 64-byte tags. This is the {@linkplain #DEFAULT_ALGORITHM default}. */
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

    /**
     * Returns the tag length. {@code verify} rejects tags of any other length.
     *
     * @return the tag length in bytes
     */
    public int tagLengthBytes() {
      return tagLengthBytes;
    }
  }

  /**
   * A secret key for HMAC signing.
   *
   * <p>Close the key when finished, ideally with try-with-resources. Closing zeroes the key
   * material and any later use throws {@link IntegrityException}. Keys are thread-safe.
   */
  public static final class Key implements AutoCloseable {

    /** Minimum key material length in bytes. */
    public static final int KEY_LENGTH_MIN = 32;

    private final byte[] material;
    private boolean closed;

    private Key(byte[] material) {
      this.material = material.clone();
    }

    /**
     * Creates an HMAC key from existing key material. The material is copied, so clear the caller's
     * array afterwards. Use {@link HmacIntegrity#generateKey()} for new keys.
     *
     * @param keyMaterial the raw key material; it is copied
     * @return a new HMAC key
     * @throws IllegalArgumentException if {@code keyMaterial} is {@code null} or contains fewer
     *     than {@value #KEY_LENGTH_MIN} bytes
     */
    public static Key of(byte[] keyMaterial) {
      if (keyMaterial == null) {
        throw new IllegalArgumentException("keyMaterial must not be null");
      }
      if (keyMaterial.length < KEY_LENGTH_MIN) {
        throw new IllegalArgumentException(
            "HMAC keys must contain at least " + KEY_LENGTH_MIN + " bytes");
      }

      return new Key(keyMaterial);
    }

    /**
     * Returns a copy of the key material. Clear the returned array when finished with it.
     *
     * @return a copy of the key material
     * @throws IntegrityException if this key has been closed
     */
    public synchronized byte[] copyMaterial() {
      if (closed) {
        throw new IntegrityException("HMAC key has been closed", null);
      }

      return material.clone();
    }

    /** Zeroes the key material. Has no effect if the key is already closed. */
    @Override
    public synchronized void close() {
      if (!closed) {
        Arrays.fill(material, (byte) 0);
        closed = true;
      }
    }
  }

  /**
   * Generates a random HMAC key.
   *
   * @return a new 64-byte HMAC key
   */
  public static Key generateKey() {
    byte[] material = new byte[GENERATED_KEY_LENGTH_BYTES];

    try {
      SECURE_RANDOM.nextBytes(material);
      return Key.of(material);
    } finally {
      Arrays.fill(material, (byte) 0);
    }
  }

  /**
   * Computes an HMAC tag using {@link #DEFAULT_ALGORITHM}.
   *
   * @param key the HMAC key
   * @param message the message to sign; may be empty
   * @return a newly allocated HMAC tag
   * @throws IllegalArgumentException if {@code key} or {@code message} is {@code null}
   * @throws IntegrityException if the key has been closed or the required algorithm is unavailable
   */
  public static byte[] sign(Key key, byte[] message) {
    return sign(key, message, DEFAULT_ALGORITHM);
  }

  /**
   * Computes an HMAC tag using a specific algorithm.
   *
   * @param key the HMAC key
   * @param message the message to sign; may be empty
   * @param algorithm the HMAC algorithm to use
   * @return a newly allocated HMAC tag of {@link Algorithm#tagLengthBytes()} bytes
   * @throws IllegalArgumentException if any argument is {@code null}
   * @throws IntegrityException if the key has been closed or the required algorithm is unavailable
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
   * @param expectedTag a tag previously returned by {@link #sign(Key, byte[])}
   * @return {@code true} if the tag matches the message, {@code false} otherwise
   * @throws IllegalArgumentException if any argument is {@code null}, or if {@code expectedTag} is
   *     not exactly the default algorithm's tag length
   * @throws IntegrityException if the key has been closed or the required algorithm is unavailable
   */
  public static boolean verify(Key key, byte[] message, byte[] expectedTag) {
    return verify(key, message, expectedTag, DEFAULT_ALGORITHM);
  }

  /**
   * Verifies an HMAC tag using a specific algorithm.
   *
   * <p>Compares in constant time. A tag of the wrong length throws instead of returning {@code
   * false}, as it is malformed rather than mismatched.
   *
   * @param key the HMAC key
   * @param message the message to verify
   * @param expectedTag a tag previously signed with the same key and algorithm
   * @param algorithm the HMAC algorithm the tag was signed with
   * @return {@code true} if the tag matches the message, {@code false} otherwise
   * @throws IllegalArgumentException if any argument is {@code null}, or if {@code expectedTag} is
   *     not exactly {@link Algorithm#tagLengthBytes()} bytes long
   * @throws IntegrityException if the key has been closed or the required algorithm is unavailable
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
          "expectedTag must be "
              + algorithm.tagLengthBytes()
              + " bytes for "
              + algorithm
              + " but was "
              + expectedTag.length);
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
      throw new IntegrityException(
          "Required HMAC algorithm is unavailable: " + algorithm.jcaName(), e);
    }
  }
}
