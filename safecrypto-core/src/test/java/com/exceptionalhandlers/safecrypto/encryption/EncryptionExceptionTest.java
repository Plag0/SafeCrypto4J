package com.exceptionalhandlers.safecrypto.encryption;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Tests for {@link EncryptionException}. */
@DisplayName("EncryptionException")
class EncryptionExceptionTest {

  @Test
  @DisplayName("preserves the provided message")
  void preservesMessage() {
    String message = "AES-GCM encryption failed";
    EncryptionException ex = new EncryptionException(message, new Exception());

    assertThat(ex).hasMessage(message);
  }

  @Test
  @DisplayName("getCause() returns the exact cause instance provided at construction")
  void causeIsAccessibleViaGetCause() {
    Throwable cause = new IllegalStateException("provider not found");
    EncryptionException ex = new EncryptionException("msg", cause);

    assertThat(ex.getCause()).isSameAs(cause);
  }
}
