package com.exceptionalhandlers.safecrypto.integrity;

import static org.assertj.core.api.Assertions.assertThat;

import com.exceptionalhandlers.safecrypto.SafeCryptoException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Tests for {@link IntegrityException}. */
@DisplayName("IntegrityException")
class IntegrityExceptionTest {

  @Test
  @DisplayName("preserves the provided message")
  void preservesMessage() {
    String message = "Required HMAC algorithm is unavailable: HmacSHA512";
    IntegrityException ex = new IntegrityException(message, new Exception());

    assertThat(ex).hasMessage(message);
  }

  @Test
  @DisplayName("getCause() returns the exact cause instance provided at construction")
  void causeIsAccessibleViaGetCause() {
    Throwable cause = new IllegalStateException("provider not found");
    IntegrityException ex = new IntegrityException("msg", cause);

    assertThat(ex.getCause()).isSameAs(cause);
  }

  @Test
  @DisplayName("allows a null cause, as used for a closed key")
  void allowsNullCause() {
    IntegrityException ex = new IntegrityException("HMAC key has been closed", null);

    assertThat(ex.getCause()).isNull();
  }

  @Test
  @DisplayName("is a SafeCryptoException")
  void isSafeCryptoException() {
    assertThat(new IntegrityException("msg", null)).isInstanceOf(SafeCryptoException.class);
  }
}
