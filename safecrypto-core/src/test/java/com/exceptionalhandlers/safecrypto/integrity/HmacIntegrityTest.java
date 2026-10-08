package com.exceptionalhandlers.safecrypto.integrity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("HmacIntegrity")
class HmacIntegrityTest {
  /** predictable key material for testing */
  private static final byte[] KEY_MATERIAL =
      new byte[] {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f
      };

  private static final byte[] MESSAGE =
      "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);

  /** Uses builtin java hmac to create a comparable reference. */
  private static byte[] referenceHmac(HmacIntegrity.Algorithm algorithm, byte[] key, byte[] message)
      throws Exception {

    String javaAlgorithm =
        switch (algorithm) {
          case SHA256 -> "HmacSHA256";
          case SHA384 -> "HmacSHA384";
          case SHA512 -> "HmacSHA512";
        };

    Mac mac = Mac.getInstance(javaAlgorithm);
    mac.init(new SecretKeySpec(key, javaAlgorithm));
    return mac.doFinal(message);
  }

  @Test
  @DisplayName("ensures that null key material isn't accepted")
  void keyMaterialMustNotBeNull() {
    assertThatThrownBy(() -> HmacIntegrity.Key.of(null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Nested
  @DisplayName("key generation")
  class KeyGeneration {
    @Test
    @DisplayName("ensures that short key material isn't accepted")
    void keyMaterialMustContainAtLeast32Bytes() {
      byte[] tooShort = new byte[31];

      assertThatThrownBy(() -> HmacIntegrity.Key.of(tooShort))
          .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("checks that key creation with good material works.")
    void exactly32ByteKeyIsAccepted() {
      assertThatCode(() -> HmacIntegrity.Key.of(new byte[32])).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("checks that key material cant be modified after key creation")
    void keyMaterialIsDefensivelyCopiedOnCreation() {
      byte[] original = KEY_MATERIAL.clone();

      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(original)) {

        byte[] expectedBeforeMutation =
            HmacIntegrity.sign(key, MESSAGE, HmacIntegrity.Algorithm.SHA256);

        Arrays.fill(original, (byte) 0x7f);

        byte[] actualAfterMutation =
            HmacIntegrity.sign(key, MESSAGE, HmacIntegrity.Algorithm.SHA256);

        assertThat(actualAfterMutation).containsExactly(expectedBeforeMutation);
      }
    }

    @Test
    @DisplayName("checks that generateKey() generates a key that is usable")
    void generatedKeyCanBeUsedForSigning() {
      try (HmacIntegrity.Key key = HmacIntegrity.generateKey()) {

        byte[] tag = HmacIntegrity.sign(key, MESSAGE, HmacIntegrity.Algorithm.SHA256);

        assertThat(tag).isNotNull().hasSize(32);
      }
    }

    @Test
    @DisplayName("checks that generateKey() generates unique keys")
    void generatedKeysAreNotAlwaysIdentical() {
      try (HmacIntegrity.Key first = HmacIntegrity.generateKey();
          HmacIntegrity.Key second = HmacIntegrity.generateKey()) {

        byte[] firstTag = HmacIntegrity.sign(first, MESSAGE, HmacIntegrity.Algorithm.SHA256);
        byte[] secondTag = HmacIntegrity.sign(second, MESSAGE, HmacIntegrity.Algorithm.SHA256);

        assertThat(MessageDigest.isEqual(firstTag, secondTag)).isFalse();
      }
    }

    @Test
    @DisplayName("check that closed keys throw when used")
    void closedKeyCannotExposeMaterial() {
      HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL);

      key.close();

      assertThatThrownBy(key::copyMaterial).isInstanceOf(IntegrityException.class);
    }
  }

  @Nested
  @DisplayName("Signing and Verification")
  class SignAndVerify {
    @Test
    @DisplayName("checks that signing produces the same output as Java's signing")
    void signMatchesJavaReference() throws Exception {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {

        for (HmacIntegrity.Algorithm algorithm : HmacIntegrity.Algorithm.values()) {
          byte[] expected = referenceHmac(algorithm, KEY_MATERIAL, MESSAGE);
          byte[] actual = HmacIntegrity.sign(key, MESSAGE, algorithm);

          assertThat(actual)
              .withFailMessage("Mismatched tags for %s", algorithm)
              .containsExactly(expected);
        }
      }
    }

    @Test
    @DisplayName("ensures that the produced tags are of the correct length for each algorithm.")
    void signProducesExpectedTagLengths() {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {
        assertThat(HmacIntegrity.sign(key, MESSAGE, HmacIntegrity.Algorithm.SHA256)).hasSize(32);

        assertThat(HmacIntegrity.sign(key, MESSAGE, HmacIntegrity.Algorithm.SHA384)).hasSize(48);

        assertThat(HmacIntegrity.sign(key, MESSAGE, HmacIntegrity.Algorithm.SHA512)).hasSize(64);
      }
    }

    @Test
    @DisplayName("rejects null signing arguments")
    void signingRequiresNonNullArguments() {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {

        assertThatThrownBy(() -> HmacIntegrity.sign(null, MESSAGE))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> HmacIntegrity.sign(key, null))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> HmacIntegrity.sign(key, MESSAGE, null))
            .isInstanceOf(IllegalArgumentException.class);
      }
    }

    @Test
    @DisplayName("checks a full round trip, ensuring that produced tags can be verified")
    void verificationSucceedsForValidTag() {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {

        for (HmacIntegrity.Algorithm algorithm : HmacIntegrity.Algorithm.values()) {
          byte[] tag = HmacIntegrity.sign(key, MESSAGE, algorithm);

          assertThat(HmacIntegrity.verify(key, MESSAGE, tag, algorithm))
              .withFailMessage("Correct tag was rejected for algorithm %s", algorithm)
              .isTrue();
        }
      }
    }

    @Test
    @DisplayName("ensures that a modified message fails verification")
    void verifyFailsForModifiedMessage() {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {

        byte[] tag = HmacIntegrity.sign(key, MESSAGE);
        byte[] modifiedMessage = MESSAGE.clone();
        modifiedMessage[0] = '!'; // was 'T'

        assertThat(HmacIntegrity.verify(key, modifiedMessage, tag)).isFalse();
      }
    }

    @Test
    @DisplayName("ensures that verification with the wrong key")
    void verifyFailsForIncorrectKey() {
      try (HmacIntegrity.Key goodKey = HmacIntegrity.Key.of(KEY_MATERIAL);
          HmacIntegrity.Key badKey = HmacIntegrity.generateKey()) {

        byte[] tag = HmacIntegrity.sign(goodKey, MESSAGE);

        assertThat(HmacIntegrity.verify(badKey, MESSAGE, tag)).isFalse();
      }
    }

    @Test
    @DisplayName("ensures that verification only accepts tags of the expected length")
    void verifyFailsWithWrongTagLength() {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {
        assertThatThrownBy(
                () ->
                    HmacIntegrity.verify(
                        key, MESSAGE, new byte[31], HmacIntegrity.Algorithm.SHA256))
            .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(
                () ->
                    HmacIntegrity.verify(
                        key, MESSAGE, new byte[32], HmacIntegrity.Algorithm.SHA384))
            .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(
                () ->
                    HmacIntegrity.verify(
                        key, MESSAGE, new byte[48], HmacIntegrity.Algorithm.SHA512))
            .isInstanceOf(IllegalArgumentException.class);
      }
    }

    @Test
    @DisplayName("ensures that signing fails for closed keys")
    void closedKeyCannotBeUsedForSigning() {
      HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL);

      key.close();

      // should occur during copyMaterial
      assertThatThrownBy(() -> HmacIntegrity.sign(key, MESSAGE, HmacIntegrity.Algorithm.SHA256))
          .isInstanceOf(IntegrityException.class);
    }
  }
}
