package com.exceptionalhandlers.safecrypto.encryption;

import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

public class AesEncryptorTest {

  private static final SecureRandom RANDOM = new SecureRandom();

  private byte[] randomKey() {
    byte[] key = new byte[32];
    RANDOM.nextBytes(key);
    return key;
  }

  @Test
  void encryptThenDecryptReturnsOriginalPlaintext() {
    byte[] key = randomKey();
    byte[] plaintext = "Test message".getBytes();

    String encrypted = AesEncryptor.encrypt(plaintext, key);
    byte[] decrypted = AesEncryptor.decrypt(encrypted, key);

    assertArrayEquals(plaintext, decrypted);
  }

  @Test
  void decryptFailsWithWrongKey() {
    byte[] key = randomKey();
    byte[] wrongKey = randomKey();

    byte[] plaintext = "Sensitive data".getBytes();

    String encrypted = AesEncryptor.encrypt(plaintext, key);

    assertThrows(
        RuntimeException.class,
        () -> {
          AesEncryptor.decrypt(encrypted, wrongKey);
        });
  }

  @Test
  void decryptFailsIfCiphertextModified() {
    byte[] key = randomKey();
    byte[] plaintext = "Sensitive data".getBytes();

    String encrypted = AesEncryptor.encrypt(plaintext, key);

    String tampered = encrypted.substring(0, encrypted.length() - 2) + "AA";

    assertThrows(
        RuntimeException.class,
        () -> {
          AesEncryptor.decrypt(tampered, key);
        });
  }

  @Test
  void invalidKeyLengthThrowsException() {
    byte[] badKey = new byte[10];
    byte[] plaintext = "Test".getBytes();

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          AesEncryptor.encrypt(plaintext, badKey);
        });
  }

  @Test
  void invalidPayloadFormatThrowsException() {
    byte[] key = randomKey();

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          AesEncryptor.decrypt("invalid-format", key);
        });
  }
}
