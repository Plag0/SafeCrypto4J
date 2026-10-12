package com.exceptionalhandlers.safecrypto.integrity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

/** Tests for {@link HmacIntegrity}. */
@DisplayName("HmacIntegrity")
class HmacIntegrityTest {

  /** Predictable key material for testing. */
  private static final byte[] KEY_MATERIAL =
      new byte[] {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f
      };

  private static final byte[] MESSAGE =
      "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);

  /** Uses Java's built-in HMAC directly to create an independent reference tag. */
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

  @Nested
  @DisplayName("Key")
  class KeyTests {

    @Test
    @DisplayName("throws when key material is null")
    void throwsWhenKeyMaterialIsNull() {
      assertThatThrownBy(() -> HmacIntegrity.Key.of(null))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("keyMaterial must not be null");
    }

    @Test
    @DisplayName("throws when key material is shorter than 32 bytes")
    void throwsWhenKeyMaterialIsTooShort() {
      byte[] tooShort = new byte[HmacIntegrity.Key.KEY_LENGTH_MIN - 1];

      assertThatThrownBy(() -> HmacIntegrity.Key.of(tooShort))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("HMAC keys must contain at least 32 bytes");
    }

    @Test
    @DisplayName("accepts key material of exactly 32 bytes")
    void acceptsExactly32Bytes() {
      assertThatCode(() -> HmacIntegrity.Key.of(KEY_MATERIAL.clone())).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("copies key material, so later changes to the caller's array have no effect")
    void copiesKeyMaterialOnCreation() {
      byte[] original = KEY_MATERIAL.clone();

      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(original)) {
        byte[] before = HmacIntegrity.sign(key, MESSAGE, HmacIntegrity.Algorithm.SHA256);

        Arrays.fill(original, (byte) 0x7f);

        byte[] after = HmacIntegrity.sign(key, MESSAGE, HmacIntegrity.Algorithm.SHA256);
        assertThat(after).containsExactly(before);
      }
    }

    @Test
    @DisplayName("copyMaterial() returns a copy that callers cannot use to change the key")
    void copyMaterialReturnsACopy() {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {
        byte[] copy = key.copyMaterial();
        assertThat(copy).containsExactly(KEY_MATERIAL);

        Arrays.fill(copy, (byte) 0);

        assertThat(key.copyMaterial()).containsExactly(KEY_MATERIAL);
      }
    }

    @Test
    @DisplayName("throws when copying the material of a closed key")
    void closedKeyCannotExposeMaterial() {
      HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL);

      key.close();

      assertThatThrownBy(key::copyMaterial)
          .isInstanceOf(IntegrityException.class)
          .hasMessage("HMAC key has been closed");
    }

    @Test
    @DisplayName("closing a key twice has no further effect")
    void closingTwiceIsHarmless() {
      HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL);

      key.close();

      assertThatCode(key::close).doesNotThrowAnyException();
    }
  }

  @Nested
  @DisplayName("generateKey()")
  class GenerateKey {

    @Test
    @DisplayName("generates 64 bytes of key material")
    void generates64ByteKeys() {
      try (HmacIntegrity.Key key = HmacIntegrity.generateKey()) {
        assertThat(key.copyMaterial()).hasSize(64);
      }
    }

    @Test
    @DisplayName("generates a key that can sign and verify")
    void generatedKeyCanSignAndVerify() {
      try (HmacIntegrity.Key key = HmacIntegrity.generateKey()) {
        byte[] tag = HmacIntegrity.sign(key, MESSAGE);

        assertThat(HmacIntegrity.verify(key, MESSAGE, tag)).isTrue();
      }
    }

    @Test
    @DisplayName("generates a different key each time")
    void generatedKeysDiffer() {
      try (HmacIntegrity.Key first = HmacIntegrity.generateKey();
          HmacIntegrity.Key second = HmacIntegrity.generateKey()) {

        assertThat(MessageDigest.isEqual(first.copyMaterial(), second.copyMaterial())).isFalse();
      }
    }
  }

  @Nested
  @DisplayName("sign()")
  class Sign {

    @ParameterizedTest(name = "{0}")
    @EnumSource(HmacIntegrity.Algorithm.class)
    @DisplayName("produces the same tag as Java's built-in HMAC")
    void matchesJavaReference(HmacIntegrity.Algorithm algorithm) throws Exception {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {
        byte[] expected = referenceHmac(algorithm, KEY_MATERIAL, MESSAGE);

        assertThat(HmacIntegrity.sign(key, MESSAGE, algorithm)).containsExactly(expected);
      }
    }

    @ParameterizedTest(name = "{0} produces {1}-byte tags")
    @CsvSource({"SHA256, 32", "SHA384, 48", "SHA512, 64"})
    @DisplayName("produces tags of the algorithm's documented length")
    void producesExpectedTagLengths(HmacIntegrity.Algorithm algorithm, int expectedLength) {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {
        assertThat(algorithm.tagLengthBytes()).isEqualTo(expectedLength);
        assertThat(HmacIntegrity.sign(key, MESSAGE, algorithm)).hasSize(expectedLength);
      }
    }

    @Test
    @DisplayName("uses SHA-512 when no algorithm is given")
    void defaultsToSha512() {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {
        // Tags don't record their algorithm, so changing the default would break stored tags.
        assertThat(HmacIntegrity.DEFAULT_ALGORITHM).isEqualTo(HmacIntegrity.Algorithm.SHA512);
        assertThat(HmacIntegrity.sign(key, MESSAGE))
            .containsExactly(HmacIntegrity.sign(key, MESSAGE, HmacIntegrity.Algorithm.SHA512));
      }
    }

    @Test
    @DisplayName("signs an empty message")
    void signsEmptyMessage() {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {
        byte[] tag = HmacIntegrity.sign(key, new byte[0]);

        assertThat(HmacIntegrity.verify(key, new byte[0], tag)).isTrue();
      }
    }

    @Test
    @DisplayName("throws when any argument is null")
    void throwsWhenArgumentIsNull() {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {
        assertThatThrownBy(() -> HmacIntegrity.sign(null, MESSAGE))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("key must not be null");
        assertThatThrownBy(() -> HmacIntegrity.sign(key, null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("message must not be null");
        assertThatThrownBy(() -> HmacIntegrity.sign(key, MESSAGE, null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("algorithm must not be null");
      }
    }

    @Test
    @DisplayName("throws when the key has been closed")
    void throwsWhenKeyIsClosed() {
      HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL);
      key.close();

      assertThatThrownBy(() -> HmacIntegrity.sign(key, MESSAGE))
          .isInstanceOf(IntegrityException.class);
    }
  }

  @Nested
  @DisplayName("verify()")
  class Verify {

    @ParameterizedTest(name = "{0}")
    @EnumSource(HmacIntegrity.Algorithm.class)
    @DisplayName("returns true for a tag produced by sign()")
    void acceptsValidTag(HmacIntegrity.Algorithm algorithm) {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {
        byte[] tag = HmacIntegrity.sign(key, MESSAGE, algorithm);

        assertThat(HmacIntegrity.verify(key, MESSAGE, tag, algorithm)).isTrue();
      }
    }

    @Test
    @DisplayName("returns false when the message has been modified")
    void returnsFalseForModifiedMessage() {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {
        byte[] tag = HmacIntegrity.sign(key, MESSAGE);
        byte[] modified = MESSAGE.clone();
        modified[0] = '!'; // was 'T'

        assertThat(HmacIntegrity.verify(key, modified, tag)).isFalse();
      }
    }

    @ParameterizedTest(name = "flipping a bit in byte {0}")
    @CsvSource({"0", "31", "63"})
    @DisplayName("returns false when a single bit of the tag has been flipped")
    void returnsFalseForTamperedTag(int index) {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {
        byte[] tag = HmacIntegrity.sign(key, MESSAGE);
        tag[index] ^= 0x01;

        assertThat(HmacIntegrity.verify(key, MESSAGE, tag)).isFalse();
      }
    }

    @Test
    @DisplayName("returns false when verifying with the wrong key")
    void returnsFalseForWrongKey() {
      try (HmacIntegrity.Key goodKey = HmacIntegrity.Key.of(KEY_MATERIAL);
          HmacIntegrity.Key badKey = HmacIntegrity.generateKey()) {
        byte[] tag = HmacIntegrity.sign(goodKey, MESSAGE);

        assertThat(HmacIntegrity.verify(badKey, MESSAGE, tag)).isFalse();
      }
    }

    @Test
    @DisplayName("throws when the tag is not the algorithm's exact length")
    void throwsForWrongTagLength() {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {
        assertThatThrownBy(
                () ->
                    HmacIntegrity.verify(
                        key, MESSAGE, new byte[31], HmacIntegrity.Algorithm.SHA256))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("expectedTag must be 32 bytes for SHA256 but was 31");

        assertThatThrownBy(
                () ->
                    HmacIntegrity.verify(
                        key, MESSAGE, new byte[32], HmacIntegrity.Algorithm.SHA384))
            .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> HmacIntegrity.verify(key, MESSAGE, new byte[65]))
            .isInstanceOf(IllegalArgumentException.class);
      }
    }

    @Test
    @DisplayName("throws when verifying a tag signed with a different algorithm")
    void throwsForAlgorithmMismatch() {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {
        byte[] sha256Tag = HmacIntegrity.sign(key, MESSAGE, HmacIntegrity.Algorithm.SHA256);

        assertThatThrownBy(() -> HmacIntegrity.verify(key, MESSAGE, sha256Tag))
            .isInstanceOf(IllegalArgumentException.class);
      }
    }

    @Test
    @DisplayName("throws when any argument is null, or the tag is empty")
    void throwsForInvalidArguments() {
      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL)) {
        byte[] tag = HmacIntegrity.sign(key, MESSAGE);

        assertThatThrownBy(() -> HmacIntegrity.verify(null, MESSAGE, tag))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("key must not be null");
        assertThatThrownBy(() -> HmacIntegrity.verify(key, null, tag))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("message must not be null");
        assertThatThrownBy(() -> HmacIntegrity.verify(key, MESSAGE, null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("expectedTag must not be null or empty");
        assertThatThrownBy(() -> HmacIntegrity.verify(key, MESSAGE, new byte[0]))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("expectedTag must not be null or empty");
        assertThatThrownBy(() -> HmacIntegrity.verify(key, MESSAGE, tag, null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("algorithm must not be null");
      }
    }

    @Test
    @DisplayName("throws when the key has been closed")
    void throwsWhenKeyIsClosed() {
      HmacIntegrity.Key key = HmacIntegrity.Key.of(KEY_MATERIAL);
      byte[] tag = HmacIntegrity.sign(key, MESSAGE);
      key.close();

      assertThatThrownBy(() -> HmacIntegrity.verify(key, MESSAGE, tag))
          .isInstanceOf(IntegrityException.class);
    }
  }

  /** RFC 4231 test cases 6 and 7, the only ones with keys of at least 32 bytes. */
  @Nested
  @DisplayName("RFC 4231 known-answer tests")
  class KnownAnswers {

    private static final String TEST_CASE_6 =
        "Test Using Larger Than Block-Size Key - Hash Key First";

    private static final String TEST_CASE_7 =
        "This is a test using a larger than block-size key and a larger than block-size data."
            + " The key needs to be hashed before being used by the HMAC algorithm.";

    @ParameterizedTest(name = "{0} {1}")
    @CsvSource({
      "case 6, SHA256, 60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
      "case 6, SHA384, 4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6"
          + "0c2ef6ab4030fe8296248df163f44952",
      "case 6, SHA512, 80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
          + "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
      "case 7, SHA256, 9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
      "case 7, SHA384, 6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5"
          + "a678cc31e799176d3860e6110c46523e",
      "case 7, SHA512, e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944"
          + "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
    })
    @DisplayName("produces the published tag")
    void producesPublishedTag(String testCase, HmacIntegrity.Algorithm algorithm, String hex) {
      byte[] keyMaterial = new byte[131];
      Arrays.fill(keyMaterial, (byte) 0xaa);
      String data = testCase.equals("case 6") ? TEST_CASE_6 : TEST_CASE_7;
      byte[] message = data.getBytes(StandardCharsets.US_ASCII);

      try (HmacIntegrity.Key key = HmacIntegrity.Key.of(keyMaterial)) {
        byte[] tag = HmacIntegrity.sign(key, message, algorithm);

        assertThat(HexFormat.of().formatHex(tag)).isEqualTo(hex);
        assertThat(HmacIntegrity.verify(key, message, tag, algorithm)).isTrue();
      }
    }
  }
}
