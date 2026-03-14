package com.exceptionalhandlers.safecrypto.password;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Hashes and verifies passwords using PBKDF2 with HMAC-SHA256 and random salts.
 *
 * <p>The stored format ({@code iterations:base64Salt:base64Hash}) encodes everything needed for
 * verification. Callers never manage salts or work factors directly.
 *
 * <pre>{@code
 * char[] password = getPasswordFromUser();
 * String stored = PasswordHasher.hashPassword(password);
 * Arrays.fill(password, '\0');
 *
 * char[] attempt = getPasswordFromUser();
 * boolean ok = PasswordHasher.verifyPassword(attempt, stored);
 * Arrays.fill(attempt, '\0');
 * }</pre>
 *
 * <h3>Protections</h3>
 *
 * <ul>
 *   <li>Offline dictionary attacks, slowed by the PBKDF2 work factor
 *   <li>Rainbow table attacks, defeated by per-password random salts
 *   <li>Timing attacks, prevented by constant time comparison
 *   <li>Password retention in JVM memory, reduced via {@code char[]} with explicit clearing
 * </ul>
 *
 * <h3>Out of scope</h3>
 *
 * <ul>
 *   <li>Database compromise. An attacker with the hash store can still run an offline attack.
 *   <li>Credential interception before this API is reached, for example via keyloggers.
 *   <li>Insecure hash storage. Restrict access to wherever hashes are persisted.
 *   <li>Transport security. Passwords must travel over TLS before reaching this code.
 * </ul>
 */
public final class PasswordHasher {
  private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

  /** Output size of SHA-256, and therefore of each PBKDF2 derived key in this class. */
  private static final int SHA256_OUTPUT_BITS = 256;

  private static final int SALT_LENGTH_BYTES = 16;

  /**
   * Work factor for new hashes. OWASP recommends ≥ 600,000 iterations of PBKDF2-HMAC-SHA256 as of
   * 2023.
   */
  private static final int DEFAULT_ITERATIONS = 600_000;

  /**
   * Minimum iteration count accepted when verifying a stored hash. Rejects hashes that have been
   * tampered down to a trivially cheap work factor.
   */
  private static final int MINIMUM_ITERATIONS = 100_000;

  /** Shared instance. {@link SecureRandom} is thread-safe and avoids repeated seeding. */
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  /** Delimiter used in the stored hash format. */
  private static final String DELIMITER = ":";

  /** Expected number of segments in a stored hash string. */
  private static final int STORED_HASH_SEGMENT_COUNT = 3;

  // Non-instantiable utility class.
  private PasswordHasher() {}

  /**
   * Hashes a password with a fresh random salt and the default work factor.
   *
   * <p>Zero out the {@code password} array after calling this method.
   *
   * @param password the plaintext password; must not be {@code null} or empty
   * @return a formatted string {@code iterations:base64Salt:base64Hash} suitable for storage
   * @throws IllegalArgumentException if {@code password} is {@code null} or empty
   * @throws PasswordHashingException if the JVM does not support PBKDF2WithHmacSHA256
   */
  public static String hashPassword(char[] password) {
    validatePassword(password);

    byte[] salt = new byte[SALT_LENGTH_BYTES];
    SECURE_RANDOM.nextBytes(salt);

    byte[] hash = derivePbkdf2Hash(password, salt, DEFAULT_ITERATIONS);

    String encodedSalt = Base64.getEncoder().encodeToString(salt);
    String encodedHash = Base64.getEncoder().encodeToString(hash);

    return DEFAULT_ITERATIONS + DELIMITER + encodedSalt + DELIMITER + encodedHash;
  }

  /**
   * Verifies a password against a stored hash produced by {@link #hashPassword}.
   *
   * <p>The comparison runs in constant time to resist timing attacks. Format errors in {@code
   * storedHash} throw rather than returning {@code false}, so callers can distinguish a wrong
   * password from a corrupt or tampered stored value.
   *
   * <p>Zero out the {@code password} array after calling this method.
   *
   * @param password the plaintext password to verify; must not be {@code null} or empty
   * @param storedHash a value previously returned by {@link #hashPassword}; must not be {@code
   *     null} or empty
   * @return {@code true} if the password matches the stored hash, {@code false} otherwise
   * @throws IllegalArgumentException if {@code password} or {@code storedHash} is {@code null} or
   *     empty, if {@code storedHash} is not in the expected format, if the encoded iteration count
   *     is below the minimum threshold, or if the salt or hash segments have invalid lengths
   * @throws PasswordHashingException if the JVM does not support PBKDF2WithHmacSHA256
   */
  public static boolean verifyPassword(char[] password, String storedHash) {
    validatePassword(password);
    validateStoredHash(storedHash);

    String[] parts = storedHash.split(DELIMITER, STORED_HASH_SEGMENT_COUNT);
    if (parts.length != STORED_HASH_SEGMENT_COUNT) {
      throw new IllegalArgumentException(
          "Stored hash must contain exactly "
              + STORED_HASH_SEGMENT_COUNT
              + " colon-separated segments");
    }

    int iterations = parseIterations(parts[0]);
    byte[] salt = decodeBase64Segment(parts[1], "salt");
    if (salt.length != SALT_LENGTH_BYTES) {
      throw new IllegalArgumentException("stored salt has invalid length " + salt.length);
    }

    byte[] expectedHash = decodeBase64Segment(parts[2], "hash");
    if (expectedHash.length != SHA256_OUTPUT_BITS / Byte.SIZE) {
      throw new IllegalArgumentException("stored hash has invalid length " + expectedHash.length);
    }

    byte[] actualHash = derivePbkdf2Hash(password, salt, iterations);

    return MessageDigest.isEqual(expectedHash, actualHash);
  }

  /**
   * Derives a PBKDF2-HMAC-SHA256 hash from the given inputs.
   *
   * <p>{@link PBEKeySpec} is always cleared in the finally block, even if derivation throws, so the
   * password copy held by the spec does not linger in memory.
   */
  private static byte[] derivePbkdf2Hash(char[] password, byte[] salt, int iterations) {
    PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, SHA256_OUTPUT_BITS);
    try {
      SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
      return factory.generateSecret(spec).getEncoded();
    } catch (NoSuchAlgorithmException e) {
      throw new PasswordHashingException(PBKDF2_ALGORITHM + " is not available in this JVM", e);
    } catch (InvalidKeySpecException e) {
      throw new PasswordHashingException("key derivation failed with the provided parameters", e);
    } finally {
      spec.clearPassword();
    }
  }

  private static void validatePassword(char[] password) {
    if (password == null || password.length == 0) {
      throw new IllegalArgumentException("password must not be null or empty");
    }
  }

  private static void validateStoredHash(String storedHash) {
    if (storedHash == null || storedHash.isEmpty()) {
      throw new IllegalArgumentException("storedHash must not be null or empty");
    }
  }

  /** Parses and validates the iteration count from a stored hash segment. */
  private static int parseIterations(String segment) {
    int iterations;
    try {
      iterations = Integer.parseInt(segment);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(
          "stored hash contains a non-integer iteration count: \"" + segment + "\"", e);
    }

    if (iterations < MINIMUM_ITERATIONS) {
      throw new IllegalArgumentException(
          "stored hash iteration count "
              + iterations
              + " is below the minimum permitted value of "
              + MINIMUM_ITERATIONS);
    }

    return iterations;
  }

  // segmentName is included in the exception message to identify which segment was invalid.
  private static byte[] decodeBase64Segment(String segment, String segmentName) {
    try {
      return Base64.getDecoder().decode(segment);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(
          "stored hash contains an invalid Base64-encoded " + segmentName, e);
    }
  }
}
