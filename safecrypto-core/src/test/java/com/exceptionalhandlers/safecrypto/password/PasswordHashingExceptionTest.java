package com.exceptionalhandlers.safecrypto.password;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Tests for {@link PasswordHashingException}. */
@DisplayName("PasswordHashingException")
class PasswordHashingExceptionTest {

  @Test
  @DisplayName("preserves the provided message")
  void preservesMessage() {
    String message = "PBKDF2WithHmacSHA256 is not available in this JVM";
    PasswordHashingException ex = new PasswordHashingException(message, new Exception());

    assertThat(ex).hasMessage(message);
  }

  @Test
  @DisplayName("getCause() returns the exact cause instance provided at construction")
  void causeIsAccessibleViaGetCause() {
    Throwable cause = new IllegalStateException("provider not found");
    PasswordHashingException ex = new PasswordHashingException("msg", cause);

    assertThat(ex.getCause()).isSameAs(cause);
  }
}
