package com.exceptionalhandlers.safecrypto.encryption;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts and decrypts data using AES in GCM mode.
 *
 * <p>This class provides a simple, safe-by-default interface for symmetric encryption. Callers
 * provide plaintext and a secret key, and the library handles IV generation, encryption
 * configuration, and packaging the result for storage.
 *
 * <pre>{@code
 * byte[] key = getKeyFromSecureSource();
 * byte[] plaintext = "Sensitive data".getBytes(StandardCharsets.UTF_8);
 *
 * String encrypted = AesEncryptor.encrypt(plaintext, key);
 *
 * byte[] decrypted = AesEncryptor.decrypt(encrypted, key);
 *
 * Arrays.fill(plaintext, (byte) 0);
 * Arrays.fill(key, (byte) 0);
 * }</pre>
 *
 * <h3>Protections</h3>
 *
 * <ul>
 *   <li>Confidentiality through AES encryption
 *   <li>Integrity and authenticity through GCM authentication tags
 *   <li>IV reuse prevention via random IV generation
 * </ul>
 *
 * <h3>Out of scope</h3>
 *
 * <ul>
 *   <li>Key management. Callers must securely generate and store encryption keys.
 *   <li>Transport security. Data should still be transmitted over TLS.
 *   <li>Host compromise. An attacker controlling the JVM can access keys in memory.
 * </ul>
 *
 * <p>The stored format ({@code base64IV:base64Ciphertext}) contains everything required to decrypt
 * the payload except the secret key.
 */
public final class AesEncryptor {

  private static final String AES_ALGORITHM = "AES";
  private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";

  /** AES-GCM standard IV length. */
  private static final int IV_LENGTH_BYTES = 12;

  /** GCM authentication tag length. */
  private static final int GCM_TAG_LENGTH_BITS = 128;

  /** Delimiter used in the encrypted payload format. */
  private static final String DELIMITER = ":";

  /** Expected number of segments in the stored encrypted string. */
  private static final int STORED_SEGMENT_COUNT = 2;

  /** Shared SecureRandom instance for IV generation. */
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  // Non-instantiable utility class.
  private AesEncryptor() {}

  /**
   * Encrypts plaintext using AES-GCM with a randomly generated IV.
   *
   * <p>The returned value contains the IV and ciphertext encoded as Base64.
   *
   * <p>Zero out the {@code plaintext} and {@code key} arrays after calling this method.
   *
   * @param plaintext the data to encrypt; must not be {@code null} or empty
   * @param key the AES key; must be 16, 24, or 32 bytes
   * @return formatted encrypted payload {@code base64IV:base64Ciphertext}
   * @throws IllegalArgumentException if inputs are invalid
   * @throws EncryptionException if the JVM cannot perform AES-GCM encryption
   */
  public static String encrypt(byte[] plaintext, byte[] key) {
    validatePlaintext(plaintext);
    validateKey(key);

    byte[] iv = new byte[IV_LENGTH_BYTES];
    SECURE_RANDOM.nextBytes(iv);

    SecretKeySpec keySpec = new SecretKeySpec(key, AES_ALGORITHM);
    GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);

    try {
      Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

      byte[] ciphertext = cipher.doFinal(plaintext);

      String encodedIv = Base64.getEncoder().encodeToString(iv);
      String encodedCiphertext = Base64.getEncoder().encodeToString(ciphertext);

      return encodedIv + DELIMITER + encodedCiphertext;
    } catch (GeneralSecurityException e) {
      throw new EncryptionException("AES-GCM encryption failed", e);
    }
  }

  /**
   * Decrypts an encrypted payload produced by {@link #encrypt}.
   *
   * <p>If the ciphertext has been tampered with, AES-GCM authentication will fail and an exception
   * will be thrown.
   *
   * <p>Zero out the {@code key} array after calling this method.
   *
   * @param encryptedPayload formatted encrypted string {@code base64IV:base64Ciphertext}
   * @param key AES key used for encryption
   * @return decrypted plaintext
   * @throws IllegalArgumentException if the payload format is invalid
   * @throws EncryptionException if decryption fails or the authentication check fails
   */
  public static byte[] decrypt(String encryptedPayload, byte[] key) {
    validateEncryptedPayload(encryptedPayload);
    validateKey(key);

    String[] parts = encryptedPayload.split(DELIMITER, STORED_SEGMENT_COUNT);
    if (parts.length != STORED_SEGMENT_COUNT) {
      throw new IllegalArgumentException(
          "encrypted payload must contain exactly "
              + STORED_SEGMENT_COUNT
              + " colon-separated segments");
    }

    byte[] iv = decodeBase64Segment(parts[0], "IV");
    if (iv.length != IV_LENGTH_BYTES) {
      throw new IllegalArgumentException("stored IV has invalid length " + iv.length);
    }

    byte[] ciphertext = decodeBase64Segment(parts[1], "ciphertext");
    if (ciphertext.length < GCM_TAG_LENGTH_BITS / Byte.SIZE) {
      throw new IllegalArgumentException("ciphertext is too short");
    }

    SecretKeySpec keySpec = new SecretKeySpec(key, AES_ALGORITHM);
    GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);

    try {
      Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
      cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
      return cipher.doFinal(ciphertext);
    } catch (AEADBadTagException e) {
      throw new EncryptionException(
          "AES-GCM decryption failed because the ciphertext or key was invalid", e);
    } catch (GeneralSecurityException e) {
      throw new EncryptionException("AES-GCM decryption failed", e);
    }
  }

  private static void validatePlaintext(byte[] plaintext) {
    if (plaintext == null || plaintext.length == 0) {
      throw new IllegalArgumentException("plaintext must not be null or empty");
    }
  }

  private static void validateEncryptedPayload(String encryptedPayload) {
    if (encryptedPayload == null || encryptedPayload.isEmpty()) {
      throw new IllegalArgumentException("encryptedPayload must not be null or empty");
    }
  }

  private static void validateKey(byte[] key) {
    if (key == null) {
      throw new IllegalArgumentException("key must not be null");
    }

    int length = key.length;
    if (!(length == 16 || length == 24 || length == 32)) {
      throw new IllegalArgumentException("AES key must be 16, 24, or 32 bytes but was " + length);
    }
  }

  private static byte[] decodeBase64Segment(String segment, String name) {
    try {
      return Base64.getDecoder().decode(segment);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(
          "encrypted payload contains an invalid Base64-encoded " + name, e);
    }
  }
}
