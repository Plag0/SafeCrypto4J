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
    assertThatThrownBy(() -> HmacIntegrity.Key.of(null)).isInstanceOf(NullPointerException.class);
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
      HmacIntegrity.Key key = HmacIntegrity.Key.of(original);

      byte[] expectedBeforeMutation =
          HmacIntegrity.sign(HmacIntegrity.Algorithm.SHA256, key, MESSAGE);

      Arrays.fill(original, (byte) 0x7f);

      byte[] actualAfterMutation = HmacIntegrity.sign(HmacIntegrity.Algorithm.SHA256, key, MESSAGE);

      assertThat(actualAfterMutation).containsExactly(expectedBeforeMutation);

      key.close();
    }

    @Test
    @DisplayName("checks that generateKey() generates a key that is usable")
    void generatedKeyCanBeUsedForSigning() {
      HmacIntegrity.Key key = HmacIntegrity.generateKey();

      try {
        byte[] tag = HmacIntegrity.sign(HmacIntegrity.Algorithm.SHA256, key, MESSAGE);

        assertThat(tag).isNotNull().hasSize(32);
      } finally {
        key.close();
      }
    }

    @Test
    @DisplayName("checks that generateKey() generates unique keys")
    void generatedKeysAreNotAlwaysIdentical() {
      HmacIntegrity.Key first = HmacIntegrity.generateKey();
      HmacIntegrity.Key second = HmacIntegrity.generateKey();

      try {
        byte[] firstTag = HmacIntegrity.sign(HmacIntegrity.Algorithm.SHA256, first, MESSAGE);
        byte[] secondTag = HmacIntegrity.sign(HmacIntegrity.Algorithm.SHA256, second, MESSAGE);

        assertThat(MessageDigest.isEqual(firstTag, secondTag)).isFalse();
      } finally {
        first.close();
        second.close();
      }
    }
  }

  @Nested
  @DisplayName("Signing and Verification")
  class SignAndVerify {
    @Test
    @DisplayName("checks that signing produces the same output as Java's signing")
    void signMatchesJavaReference() throws Exception {
      HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL);

      try {
        for (HmacIntegrity.Algorithm algorithm : HmacIntegrity.Algorithm.values()) {
          byte[] expected = referenceHmac(algorithm, KEY_MATERIAL, MESSAGE);
          byte[] actual = HmacIntegrity.sign(algorithm, key, MESSAGE);

          assertThat(actual)
              .withFailMessage("Mismatched tags for %s", algorithm)
              .containsExactly(expected);
        }
      } finally {
        key.close();
      }
    }

    @Test
    @DisplayName("ensures that the produced tags are of the correct length for each algorithm.")
    void signProducesExpectedTagLengths() {
      HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL);

      try {
        assertThat(HmacIntegrity.sign(HmacIntegrity.Algorithm.SHA256, key, MESSAGE)).hasSize(32);

        assertThat(HmacIntegrity.sign(HmacIntegrity.Algorithm.SHA384, key, MESSAGE)).hasSize(48);

        assertThat(HmacIntegrity.sign(HmacIntegrity.Algorithm.SHA512, key, MESSAGE)).hasSize(64);
      } finally {
        key.close();
      }
    }

    @Test
    @DisplayName("ensures that signing fails when the key is null")
    void signingRequiresKey() {
      assertThatThrownBy(() -> HmacIntegrity.sign(HmacIntegrity.Algorithm.SHA256, null, MESSAGE))
          .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("checks a full round trip, ensuring that produced tags can be verified")
    void verificationSucceedsForValidTag() {
      HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL);

      try {
        for (HmacIntegrity.Algorithm algorithm : HmacIntegrity.Algorithm.values()) {
          byte[] tag = HmacIntegrity.sign(algorithm, key, MESSAGE);

          assertThat(HmacIntegrity.verify(algorithm, key, MESSAGE, tag))
              .withFailMessage("Correct tag was rejected for algorithm %s", algorithm)
              .isTrue();
        }
      } finally {
        key.close();
      }
    }

    @Test
    @DisplayName("ensures that a modified message fails verification")
    void verifyFailsForModifiedMessage() {
      HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL);

      try {
        byte[] tag = HmacIntegrity.sign(HmacIntegrity.Algorithm.SHA256, key, MESSAGE);

        byte[] modifiedMessage = MESSAGE.clone();
        modifiedMessage[0] = '!'; // was 'T'

        assertThat(HmacIntegrity.verify(HmacIntegrity.Algorithm.SHA256, key, modifiedMessage, tag))
            .isFalse();
      } finally {
        key.close();
      }
    }

    @Test
    @DisplayName("ensures that verification only accepts tags of the expected length")
    void verifyFailsWithWrongTagLength() {
      HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL);

      try {
        assertThat(HmacIntegrity.verify(HmacIntegrity.Algorithm.SHA256, key, MESSAGE, new byte[31]))
            .isFalse();

        assertThat(HmacIntegrity.verify(HmacIntegrity.Algorithm.SHA384, key, MESSAGE, new byte[32]))
            .isFalse();

        assertThat(HmacIntegrity.verify(HmacIntegrity.Algorithm.SHA512, key, MESSAGE, new byte[48]))
            .isFalse();
      } finally {
        key.close();
      }
    }

    @Test
    @DisplayName("ensures that signing fails for closed keys")
    void closedKeyCannotBeUsedForSigning() {
      HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL);

      key.close();

      // should occur during copyMaterial
      assertThatThrownBy(() -> HmacIntegrity.sign(HmacIntegrity.Algorithm.SHA256, key, MESSAGE))
          .isInstanceOf(IllegalStateException.class);
    }
  }
}
