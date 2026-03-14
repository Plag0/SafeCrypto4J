package com.exceptionalhandlers.safecrypto.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Base64;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/** Tests for {@link PasswordHasher}. */
@DisplayName("PasswordHasher")
class PasswordHasherTest {
  private static final char[] VALID_PASSWORD = "correct-horse-battery-staple".toCharArray();
  private static final char[] WRONG_PASSWORD = "wrong-password".toCharArray();

  // Used where a syntactically valid stored hash is required but the verification
  // result is irrelevant, avoiding unnecessary PBKDF2 work in input validation tests.
  private static final String PLACEHOLDER_STORED_HASH =
      "600000:aGVsbG8=:aGVsbG8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

  @Nested
  @DisplayName("hashPassword()")
  class HashPassword {

    @Test
    @DisplayName("output contains exactly three colon-separated segments")
    void outputHasThreeSegments() {
      String hash = PasswordHasher.hashPassword(VALID_PASSWORD);

      assertThat(hash.split(":", 3)).hasSize(3);
    }

    @Test
    @DisplayName("first segment encodes the iteration count as a positive integer")
    void firstSegmentIsIterationCount() {
      String iterationSegment = PasswordHasher.hashPassword(VALID_PASSWORD).split(":", 3)[0];

      assertThat(iterationSegment)
          .matches("\\d+")
          .satisfies(s -> assertThat(Integer.parseInt(s)).isGreaterThan(0));
    }

    @Test
    @DisplayName("second and third segments are valid Base64")
    void saltAndHashSegmentsAreValidBase64() {
      String[] parts = PasswordHasher.hashPassword(VALID_PASSWORD).split(":", 3);

      assertThat(Base64.getDecoder().decode(parts[1])).isNotEmpty();
      assertThat(Base64.getDecoder().decode(parts[2])).isNotEmpty();
    }

    @RepeatedTest(value = 5, name = "run {currentRepetition} of {totalRepetitions}")
    @DisplayName("two hashes of the same password are not equal (salt uniqueness)")
    void twoHashesOfSamePasswordDiffer() {
      String first = PasswordHasher.hashPassword(VALID_PASSWORD);
      String second = PasswordHasher.hashPassword(VALID_PASSWORD);

      // Failure here means salt generation is broken or non-random.
      assertThat(first).isNotEqualTo(second);
    }

    @ParameterizedTest(name = "rejects null/empty password [{argumentsWithNames}]")
    @NullAndEmptySource
    @DisplayName("throws IllegalArgumentException for null or empty password")
    void rejectsNullOrEmptyPassword(char[] password) {
      assertThatThrownBy(() -> PasswordHasher.hashPassword(password))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("password");
    }
  }

  @Nested
  @DisplayName("verifyPassword() correct usage")
  class VerifyPasswordCorrect {

    @Test
    @DisplayName("returns true when password matches its own stored hash")
    void returnsTrueForMatchingPassword() {
      String stored = PasswordHasher.hashPassword(VALID_PASSWORD);

      assertThat(PasswordHasher.verifyPassword(VALID_PASSWORD, stored)).isTrue();
    }

    @Test
    @DisplayName("returns false for a different password against a valid stored hash")
    void returnsFalseForWrongPassword() {
      String stored = PasswordHasher.hashPassword(VALID_PASSWORD);

      assertThat(PasswordHasher.verifyPassword(WRONG_PASSWORD, stored)).isFalse();
    }

    @Test
    @DisplayName("returns false when password differs by a single character")
    void returnsFalseForOffByOneCharacter() {
      char[] nearlyCorrect = "correct-horse-battery-staplee".toCharArray();
      String stored = PasswordHasher.hashPassword(VALID_PASSWORD);

      assertThat(PasswordHasher.verifyPassword(nearlyCorrect, stored)).isFalse();
    }

    @Test
    @DisplayName("returns false when password differs only in case")
    void returnsFalseForWrongCase() {
      char[] wrongCase = "Correct-Horse-Battery-Staple".toCharArray();
      String stored = PasswordHasher.hashPassword(VALID_PASSWORD);

      assertThat(PasswordHasher.verifyPassword(wrongCase, stored)).isFalse();
    }

    @Test
    @DisplayName("returns false when password is a whitespace variant of the stored password")
    void returnsFalseForWhitespaceVariant() {
      // Guards against any silent trimming or normalisation in the pipeline.
      String stored = PasswordHasher.hashPassword(VALID_PASSWORD);
      char[] withLeadingSpace = (" " + new String(VALID_PASSWORD)).toCharArray();

      assertThat(PasswordHasher.verifyPassword(withLeadingSpace, stored)).isFalse();
    }

    @Test
    @DisplayName("round-trip succeeds for a password containing special characters")
    void roundTripWithSpecialCharacters() {
      char[] special = "p@$$w0rd!\"£$%^&*()".toCharArray();
      String stored = PasswordHasher.hashPassword(special);

      assertThat(PasswordHasher.verifyPassword(special, stored)).isTrue();
    }

    @Test
    @DisplayName("round-trip succeeds for a single-character password")
    void roundTripWithSingleCharacterPassword() {
      char[] single = {'x'};
      String stored = PasswordHasher.hashPassword(single);

      assertThat(PasswordHasher.verifyPassword(single, stored)).isTrue();
    }

    @Test
    @DisplayName("round-trip succeeds for a very long password (512 characters)")
    void roundTripWithVeryLongPassword() {
      char[] longPassword = "a".repeat(512).toCharArray();
      String stored = PasswordHasher.hashPassword(longPassword);

      assertThat(PasswordHasher.verifyPassword(longPassword, stored)).isTrue();
    }
  }

  @Nested
  @DisplayName("verifyPassword() input validation")
  class VerifyPasswordInputValidation {

    @ParameterizedTest(name = "rejects null/empty password [{argumentsWithNames}]")
    @NullAndEmptySource
    @DisplayName("throws IllegalArgumentException for null or empty password")
    void rejectsNullOrEmptyPassword(char[] password) {
      assertThatThrownBy(() -> PasswordHasher.verifyPassword(password, PLACEHOLDER_STORED_HASH))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("password");
    }

    @ParameterizedTest(name = "rejects null/empty storedHash [{argumentsWithNames}]")
    @NullAndEmptySource
    @DisplayName("throws IllegalArgumentException for null or empty storedHash")
    void rejectsNullOrEmptyStoredHash(String storedHash) {
      assertThatThrownBy(() -> PasswordHasher.verifyPassword(VALID_PASSWORD, storedHash))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("storedHash");
    }
  }

  @Nested
  @DisplayName("verifyPassword() stored hash format validation")
  class VerifyPasswordFormatValidation {

    @ParameterizedTest(name = "rejects malformed hash: \"{0}\"")
    @ValueSource(
        strings = {
          "onlyone", // single segment
          "600000:onlytwo", // two segments
        })
    @DisplayName("throws IllegalArgumentException when segment count is wrong")
    void rejectsWrongSegmentCount(String malformed) {
      assertThatThrownBy(() -> PasswordHasher.verifyPassword(VALID_PASSWORD, malformed))
          .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest(name = "rejects non-integer iteration count: \"{0}\"")
    @ValueSource(
        strings = {
          "abc:aGVsbG8=:aGVsbG8=", // letters
          "6e5:aGVsbG8=:aGVsbG8=", // scientific notation
          " 600000:aGVsbG8=:aGVsbG8=", // leading space
          ":aGVsbG8=:aGVsbG8=" // empty segment
        })
    @DisplayName("throws IllegalArgumentException when iteration count is not a plain integer")
    void rejectsNonIntegerIterationCount(String malformed) {
      assertThatThrownBy(() -> PasswordHasher.verifyPassword(VALID_PASSWORD, malformed))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("iteration count");
    }

    @Test
    @DisplayName("throws IllegalArgumentException when salt segment is invalid Base64")
    void rejectsInvalidBase64Salt() {
      String badSalt = "600000:not!!valid!!base64:AAAAAAAAAAAAAAAAAAAAAA==";

      assertThatThrownBy(() -> PasswordHasher.verifyPassword(VALID_PASSWORD, badSalt))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("salt");
    }

    @Test
    @DisplayName("throws IllegalArgumentException when hash segment is invalid Base64")
    void rejectsInvalidBase64Hash() {
      String badHash = "600000:AAAAAAAAAAAAAAAAAAAAAA==:not!!valid!!base64";

      assertThatThrownBy(() -> PasswordHasher.verifyPassword(VALID_PASSWORD, badHash))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("hash");
    }
  }

  @Nested
  @DisplayName("verifyPassword() work factor enforcement")
  class VerifyPasswordWorkFactorEnforcement {

    @ParameterizedTest(name = "rejects iteration count {0}")
    @ValueSource(ints = {-1, 0, 10_000, 99_999})
    @DisplayName("throws IllegalArgumentException when iteration count is below minimum threshold")
    void rejectsBelowMinimumIterations(int count) {
      String lowIterationHash = count + ":aGVsbG8=:aGVsbG8=";

      assertThatThrownBy(() -> PasswordHasher.verifyPassword(VALID_PASSWORD, lowIterationHash))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("minimum");
    }
  }

  @Nested
  @DisplayName("verifyPassword() tamper detection")
  class VerifyPasswordTamperDetection {

    @Test
    @DisplayName(
        "returns false when the hash segment is replaced with a different valid Base64 value")
    void returnsFalseWhenHashSegmentIsReplaced() {
      String stored = PasswordHasher.hashPassword(VALID_PASSWORD);
      String[] parts = stored.split(":", 3);

      String tampered = parts[0] + ":" + parts[1] + ":AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

      assertThat(PasswordHasher.verifyPassword(VALID_PASSWORD, tampered)).isFalse();
    }

    @Test
    @DisplayName(
        "returns false when the salt segment is replaced with a different valid Base64 value")
    void returnsFalseWhenSaltSegmentIsReplaced() {
      String stored = PasswordHasher.hashPassword(VALID_PASSWORD);
      String[] parts = stored.split(":", 3);

      String tampered = parts[0] + ":AAAAAAAAAAAAAAAAAAAAAA==:" + parts[2];

      assertThat(PasswordHasher.verifyPassword(VALID_PASSWORD, tampered)).isFalse();
    }

    @Test
    @DisplayName("returns false when a single byte is flipped in the stored hash segment")
    void returnsFalseWhenSingleByteFlippedInHash() {
      String stored = PasswordHasher.hashPassword(VALID_PASSWORD);
      String[] parts = stored.split(":", 3);

      byte[] hashBytes = Base64.getDecoder().decode(parts[2]);
      hashBytes[0] ^= (byte) 0xFF;
      String tampered =
          parts[0] + ":" + parts[1] + ":" + Base64.getEncoder().encodeToString(hashBytes);

      assertThat(PasswordHasher.verifyPassword(VALID_PASSWORD, tampered)).isFalse();
    }

    @Test
    @DisplayName("returns false when a valid hash for a different password is presented")
    void returnsFalseWhenHashIsForDifferentPassword() {
      String storedForWrong = PasswordHasher.hashPassword(WRONG_PASSWORD);

      assertThat(PasswordHasher.verifyPassword(VALID_PASSWORD, storedForWrong)).isFalse();
    }
  }
}
