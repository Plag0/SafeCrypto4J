package com.exceptionalhandlers.safecrypto.encryption;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("AesEncryptor")
class AesEncryptorTest {

  private static final SecureRandom RANDOM = new SecureRandom();

  private byte[] randomKey(int length) {
    byte[] key = new byte[length];
    RANDOM.nextBytes(key);
    return key;
  }

  @Nested
  @DisplayName("encrypt")
  class Encrypt {

    @Test
    @DisplayName("encrypts and decrypts a value with a 16 byte key")
    void encryptsAndDecryptsWith16ByteKey() {
      assertRoundTrip(16);
    }

    @Test
    @DisplayName("encrypts and decrypts a value with a 24 byte key")
    void encryptsAndDecryptsWith24ByteKey() {
      assertRoundTrip(24);
    }

    @Test
    @DisplayName("encrypts and decrypts a value with a 32 byte key")
    void encryptsAndDecryptsWith32ByteKey() {
      assertRoundTrip(32);
    }

    @Test
    @DisplayName("two encryptions of the same plaintext produce different outputs")
    void twoEncryptionsOfSamePlaintextDiffer() {
      byte[] key = randomKey(32);
      byte[] plaintext = "Sensitive data".getBytes(StandardCharsets.UTF_8);

      String first = AesEncryptor.encrypt(plaintext, key);
      String second = AesEncryptor.encrypt(plaintext, key);

      assertThat(first).isNotEqualTo(second);
    }

    @Test
    @DisplayName("throws when plaintext is null")
    void throwsWhenPlaintextIsNull() {
      byte[] key = randomKey(32);

      assertThatThrownBy(() -> AesEncryptor.encrypt(null, key))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("plaintext must not be null or empty");
    }

    @Test
    @DisplayName("throws when plaintext is empty")
    void throwsWhenPlaintextIsEmpty() {
      byte[] key = randomKey(32);

      assertThatThrownBy(() -> AesEncryptor.encrypt(new byte[0], key))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("plaintext must not be null or empty");
    }

    @Test
    @DisplayName("throws when key is null")
    void throwsWhenKeyIsNull() {
      byte[] plaintext = "Sensitive data".getBytes(StandardCharsets.UTF_8);

      assertThatThrownBy(() -> AesEncryptor.encrypt(plaintext, null))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("key must not be null");
    }

    @Test
    @DisplayName("throws when key length is invalid")
    void throwsWhenKeyLengthIsInvalid() {
      byte[] plaintext = "Sensitive data".getBytes(StandardCharsets.UTF_8);
      byte[] badKey = new byte[10];

      assertThatThrownBy(() -> AesEncryptor.encrypt(plaintext, badKey))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("AES key must be 16, 24, or 32 bytes but was 10");
    }
  }

  @Nested
  @DisplayName("decrypt")
  class Decrypt {

    @Test
    @DisplayName("throws when payload is null")
    void throwsWhenPayloadIsNull() {
      byte[] key = randomKey(32);

      assertThatThrownBy(() -> AesEncryptor.decrypt(null, key))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("encryptedPayload must not be null or empty");
    }

    @Test
    @DisplayName("throws when payload is empty")
    void throwsWhenPayloadIsEmpty() {
      byte[] key = randomKey(32);

      assertThatThrownBy(() -> AesEncryptor.decrypt("", key))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("encryptedPayload must not be null or empty");
    }

    @Test
    @DisplayName("throws when payload format is invalid")
    void throwsWhenPayloadFormatIsInvalid() {
      byte[] key = randomKey(32);

      assertThatThrownBy(() -> AesEncryptor.decrypt("invalid-format", key))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("encrypted payload must contain exactly 2 colon-separated segments");
    }

    @Test
    @DisplayName("throws when stored IV length is invalid")
    void throwsWhenStoredIvLengthIsInvalid() {
      byte[] key = randomKey(32);
      String shortIv = "AQI=";
      String ciphertext = "AAAAAAAAAAAAAAAAAAAAAA==";
      String payload = shortIv + ":" + ciphertext;

      assertThatThrownBy(() -> AesEncryptor.decrypt(payload, key))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("stored IV has invalid length 2");
    }

    @Test
    @DisplayName("throws when ciphertext is too short")
    void throwsWhenCiphertextIsTooShort() {
      byte[] key = randomKey(32);
      byte[] iv = new byte[12];
      RANDOM.nextBytes(iv);
      byte[] shortCiphertext = new byte[8];

      String payload =
          Base64.getEncoder().encodeToString(iv)
              + ":"
              + Base64.getEncoder().encodeToString(shortCiphertext);

      assertThatThrownBy(() -> AesEncryptor.decrypt(payload, key))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("ciphertext is too short");
    }

    @Test
    @DisplayName("throws when payload contains invalid base64")
    void throwsWhenPayloadContainsInvalidBase64() {
      byte[] key = randomKey(32);

      assertThatThrownBy(() -> AesEncryptor.decrypt("not-base64:still-not-base64", key))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("encrypted payload contains an invalid Base64-encoded");
    }

    @Test
    @DisplayName("throws when decrypting with the wrong key")
    void throwsWhenDecryptingWithWrongKey() {
      byte[] key = randomKey(32);
      byte[] wrongKey = randomKey(32);
      byte[] plaintext = "Sensitive data".getBytes(StandardCharsets.UTF_8);

      String encrypted = AesEncryptor.encrypt(plaintext, key);

      assertThatThrownBy(() -> AesEncryptor.decrypt(encrypted, wrongKey))
          .isInstanceOf(EncryptionException.class)
          .hasMessageContaining("AES-GCM decryption failed");
    }

    @Test
    @DisplayName("throws when ciphertext is modified")
    void throwsWhenCiphertextIsModified() {
      byte[] key = randomKey(32);
      byte[] plaintext = "Sensitive data".getBytes(StandardCharsets.UTF_8);

      String encrypted = AesEncryptor.encrypt(plaintext, key);
      String tampered = encrypted.substring(0, encrypted.length() - 2) + "AA";

      assertThatThrownBy(() -> AesEncryptor.decrypt(tampered, key))
          .isInstanceOf(EncryptionException.class)
          .hasMessageContaining("AES-GCM decryption failed");
    }
  }

  private void assertRoundTrip(int keyLength) {
    byte[] key = randomKey(keyLength);
    byte[] plaintext = "Sensitive data".getBytes(StandardCharsets.UTF_8);

    String encrypted = AesEncryptor.encrypt(plaintext, key);
    byte[] decrypted = AesEncryptor.decrypt(encrypted, key);

    assertThat(decrypted).isEqualTo(plaintext);
  }
}
